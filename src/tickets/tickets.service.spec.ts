import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { TicketsService } from './tickets.service';
import { NotificationsService } from './notifications.service';
import { PrismaService } from '../prisma/prisma.service';
import {
  AnalystLevel,
  ModuleName,
  NotificationType,
  TicketCategory,
  TicketStatus,
  UserRole,
} from '../generated/prisma/client';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

const mockPrismaService = {
  user: { findUnique: jest.fn(), findMany: jest.fn() },
  ticket: {
    create: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(),
  },
};
const mockNotificationsService = { notify: jest.fn() };

const analyst: AuthenticatedUser = {
  userId: 'analyst-1',
  role: UserRole.ANALYST,
  analystLevel: AnalystLevel.L1,
  tenantId: 'tenant-1',
  mustChangePassword: false,
};
const admin: AuthenticatedUser = {
  userId: 'admin-1',
  role: UserRole.ADMIN,
  analystLevel: null,
  tenantId: 'tenant-1',
  mustChangePassword: false,
};
const integrationAdmin: AuthenticatedUser = {
  userId: 'ia-1',
  role: UserRole.INTEGRATION_ADMIN,
  analystLevel: null,
  tenantId: null,
  mustChangePassword: false,
};

interface TicketFixture {
  id: string;
  tenantId: string;
  createdById: string | null;
  category: TicketCategory;
  moduleName: ModuleName | null;
  status: TicketStatus;
}

const baseTicket: TicketFixture = {
  id: 'ticket-1',
  tenantId: 'tenant-1',
  createdById: 'analyst-1',
  category: TicketCategory.MODULES,
  moduleName: ModuleName.SIEM,
  status: TicketStatus.OPEN,
};

describe('TicketsService', () => {
  let service: TicketsService;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TicketsService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: NotificationsService, useValue: mockNotificationsService },
      ],
    }).compile();

    service = module.get(TicketsService);
  });

  describe('create', () => {
    const modulesTicket = {
      title: 'SIEM unreachable',
      description: 'The SIEM login page times out since this morning.',
      category: TicketCategory.MODULES,
      moduleName: ModuleName.SIEM,
    };

    beforeEach(() => {
      mockPrismaService.user.findUnique.mockResolvedValue({
        id: 'analyst-1',
        name: 'Laverne',
        email: 'laverne@x.com',
        tenantId: 'tenant-1',
      });
      mockPrismaService.ticket.create.mockResolvedValue({ id: 'ticket-1' });
      mockPrismaService.user.findMany.mockResolvedValue([
        { id: 'admin-1' },
        { id: 'ia-1' },
      ]);
    });

    it("stores the ticket with the creator's snapshot, in the caller's tenant", async () => {
      await service.create(analyst, modulesTicket);

      expect(mockPrismaService.ticket.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: {
            tenantId: 'tenant-1',
            createdById: 'analyst-1',
            createdByName: 'Laverne',
            createdByEmail: 'laverne@x.com',
            ...modulesTicket,
          },
        }),
      );
    });

    it('notifies tenant Admins and Integration Admins for a Modules ticket, never the creator', async () => {
      await service.create(analyst, modulesTicket);

      expect(mockPrismaService.user.findMany).toHaveBeenCalledWith({
        where: {
          id: { not: 'analyst-1' },
          OR: [
            { tenantId: 'tenant-1', role: UserRole.ADMIN },
            { role: UserRole.INTEGRATION_ADMIN },
          ],
        },
        select: { id: true },
      });
      expect(mockNotificationsService.notify).toHaveBeenCalledWith(
        ['admin-1', 'ia-1'],
        'ticket-1',
        NotificationType.TICKET_CREATED,
      );
    });

    it('notifies only tenant Admins for a non-Modules ticket', async () => {
      await service.create(analyst, {
        title: 'Locked out',
        description: 'I keep getting locked out after lunch.',
        category: TicketCategory.ACCOUNT_ACCESS,
      });

      expect(mockPrismaService.user.findMany).toHaveBeenCalledWith({
        where: {
          id: { not: 'analyst-1' },
          OR: [{ tenantId: 'tenant-1', role: UserRole.ADMIN }],
        },
        select: { id: true },
      });
    });

    it('requires a module for a Modules ticket', async () => {
      await expect(
        service.create(analyst, { ...modulesTicket, moduleName: undefined }),
      ).rejects.toThrow(BadRequestException);
      expect(mockPrismaService.ticket.create).not.toHaveBeenCalled();
    });

    it('rejects a module on a non-Modules ticket', async () => {
      await expect(
        service.create(analyst, {
          ...modulesTicket,
          category: TicketCategory.OTHER,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('rejects a caller with no tenant', async () => {
      await expect(
        service.create(integrationAdmin, modulesTicket),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('list / visibility', () => {
    beforeEach(() => {
      mockPrismaService.ticket.findMany.mockResolvedValue([]);
    });

    it.each([
      ['an Admin sees their whole tenant', admin, { tenantId: 'tenant-1' }],
      [
        'an Analyst sees only their own',
        analyst,
        { tenantId: 'tenant-1', createdById: 'analyst-1' },
      ],
      [
        'an Integration Admin sees Modules tickets from every tenant',
        integrationAdmin,
        { category: TicketCategory.MODULES },
      ],
    ])('%s', async (_label, user, where) => {
      await service.list(user);

      expect(mockPrismaService.ticket.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where }),
      );
    });

    it('adds the status filter', async () => {
      await service.list(admin, TicketStatus.OPEN);

      expect(mockPrismaService.ticket.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { tenantId: 'tenant-1', status: TicketStatus.OPEN },
        }),
      );
    });

    it('404s a ticket outside what the caller may see', async () => {
      mockPrismaService.ticket.findFirst.mockResolvedValue(null);

      await expect(service.findOne(analyst, 'ticket-9')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('updateStatus', () => {
    function givenTicket(overrides: Partial<TicketFixture> = {}) {
      mockPrismaService.ticket.findFirst.mockResolvedValue({
        ...baseTicket,
        ...overrides,
      });
      mockPrismaService.ticket.update.mockResolvedValue({});
    }

    it('lets a tenant Admin move a ticket forward and notifies the creator', async () => {
      givenTicket();

      await service.updateStatus(admin, 'ticket-1', TicketStatus.IN_PROGRESS);

      expect(mockPrismaService.ticket.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'ticket-1' },
          data: {
            status: TicketStatus.IN_PROGRESS,
            statusChangedById: 'admin-1',
          },
        }),
      );
      expect(mockNotificationsService.notify).toHaveBeenCalledWith(
        ['analyst-1'],
        'ticket-1',
        NotificationType.TICKET_STATUS_CHANGED,
      );
    });

    it('lets an Integration Admin resolve a Modules ticket', async () => {
      givenTicket({ status: TicketStatus.IN_PROGRESS });

      await service.updateStatus(
        integrationAdmin,
        'ticket-1',
        TicketStatus.RESOLVED,
      );

      expect(mockPrismaService.ticket.update).toHaveBeenCalled();
    });

    it('lets a handler reopen a resolved ticket', async () => {
      givenTicket({ status: TicketStatus.RESOLVED });

      await service.updateStatus(admin, 'ticket-1', TicketStatus.OPEN);

      expect(mockPrismaService.ticket.update).toHaveBeenCalled();
    });

    it('refuses a transition outside the flow', async () => {
      givenTicket({ status: TicketStatus.RESOLVED });

      await expect(
        service.updateStatus(admin, 'ticket-1', TicketStatus.IN_PROGRESS),
      ).rejects.toThrow(ConflictException);
    });

    it('refuses setting the current status again', async () => {
      givenTicket();

      await expect(
        service.updateStatus(admin, 'ticket-1', TicketStatus.OPEN),
      ).rejects.toThrow(ConflictException);
    });

    it('lets the creator withdraw their own ticket without notifying themselves', async () => {
      givenTicket({ category: TicketCategory.OTHER, moduleName: null });

      await service.updateStatus(analyst, 'ticket-1', TicketStatus.RESOLVED);

      expect(mockPrismaService.ticket.update).toHaveBeenCalled();
      expect(mockNotificationsService.notify).not.toHaveBeenCalled();
    });

    it('does not let the creator do anything but withdraw', async () => {
      givenTicket();

      await expect(
        service.updateStatus(analyst, 'ticket-1', TicketStatus.IN_PROGRESS),
      ).rejects.toThrow(ForbiddenException);
      expect(mockPrismaService.ticket.update).not.toHaveBeenCalled();
    });

    it('does not let an Admin of another tenant touch the ticket', async () => {
      givenTicket({ tenantId: 'tenant-2' });

      await expect(
        service.updateStatus(admin, 'ticket-1', TicketStatus.IN_PROGRESS),
      ).rejects.toThrow(ForbiddenException);
    });
  });
});
