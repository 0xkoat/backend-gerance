import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { SoarController } from './soar.controller';
import { SoarService } from './soar.service';
import { SoarExecutionStatus, UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { CreateSoarPlaybookDto } from './dto/createSoarPlaybook.dto';
import { SoarQueryDto } from './dto/soarQuery.dto';

const mockSoarService = {
  listPlaybooks: jest.fn(),
  createPlaybook: jest.fn(),
  updatePlaybook: jest.fn(),
  deletePlaybook: jest.fn(),
  query: jest.fn(),
};

describe('SoarController', () => {
  let controller: SoarController;

  const analyst: AuthenticatedUser = {
    userId: 'user-1',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const admin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const noTenantAdmin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: null,
    mustChangePassword: false,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SoarController],
      providers: [{ provide: SoarService, useValue: mockSoarService }],
    }).compile();

    controller = module.get<SoarController>(SoarController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('listPlaybooks', () => {
    it('returns playbooks for the caller tenant', async () => {
      const playbooks = [{ id: 'playbook-1', tenantId: 'tenant-1' }];
      mockSoarService.listPlaybooks.mockResolvedValue(playbooks);

      const result = await controller.listPlaybooks(analyst);

      expect(result).toEqual(playbooks);
      expect(mockSoarService.listPlaybooks).toHaveBeenCalledWith('tenant-1');
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.listPlaybooks(noTenantAdmin)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockSoarService.listPlaybooks).not.toHaveBeenCalled();
    });
  });

  describe('createPlaybook', () => {
    const dto: CreateSoarPlaybookDto = {
      name: 'Isolate host on critical alert',
      triggerCondition: { severity: 'CRITICAL' },
      actions: { isolateHost: true },
    };

    it('creates a playbook scoped to the caller tenant', async () => {
      const created = { id: 'playbook-1', tenantId: 'tenant-1', ...dto };
      mockSoarService.createPlaybook.mockResolvedValue(created);

      const result = await controller.createPlaybook(admin, dto);

      expect(result).toEqual(created);
      expect(mockSoarService.createPlaybook).toHaveBeenCalledWith(
        'tenant-1',
        dto,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.createPlaybook(noTenantAdmin, dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockSoarService.createPlaybook).not.toHaveBeenCalled();
    });
  });

  describe('updatePlaybook', () => {
    it('passes the tenant and id to the service', async () => {
      const updated = {
        id: 'playbook-1',
        tenantId: 'tenant-1',
        isActive: false,
      };
      mockSoarService.updatePlaybook.mockResolvedValue(updated);

      const result = await controller.updatePlaybook(admin, 'playbook-1', {
        isActive: false,
      });

      expect(result).toEqual(updated);
      expect(mockSoarService.updatePlaybook).toHaveBeenCalledWith(
        'tenant-1',
        'playbook-1',
        { isActive: false },
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updatePlaybook(noTenantAdmin, 'playbook-1', {
          isActive: false,
        }),
      ).rejects.toThrow(ForbiddenException);
      expect(mockSoarService.updatePlaybook).not.toHaveBeenCalled();
    });
  });

  describe('deletePlaybook', () => {
    it('passes the tenant and id to the service', async () => {
      mockSoarService.deletePlaybook.mockResolvedValue(undefined);

      await controller.deletePlaybook(admin, 'playbook-1');

      expect(mockSoarService.deletePlaybook).toHaveBeenCalledWith(
        'tenant-1',
        'playbook-1',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.deletePlaybook(noTenantAdmin, 'playbook-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockSoarService.deletePlaybook).not.toHaveBeenCalled();
    });
  });

  describe('queryExecutions', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: SoarQueryDto = {
        status: SoarExecutionStatus.SUCCESS,
        page: 1,
        pageSize: 20,
      };
      mockSoarService.query.mockResolvedValue([]);

      await controller.queryExecutions(analyst, query);

      expect(mockSoarService.query).toHaveBeenCalledWith({
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.queryExecutions(noTenantAdmin, {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockSoarService.query).not.toHaveBeenCalled();
    });
  });
});
