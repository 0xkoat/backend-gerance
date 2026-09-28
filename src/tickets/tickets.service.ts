import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import {
  NotificationType,
  Prisma,
  TicketCategory,
  TicketStatus,
  UserRole,
} from '../generated/prisma/client';
import type { Ticket } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { NotificationsService } from './notifications.service';
import { CreateTicketDto } from './dto/createTicket.dto';

const LIST_LIMIT = 100;

// Handlers move a ticket forward, or reopen a resolved one.
const HANDLER_TRANSITIONS: Record<TicketStatus, TicketStatus[]> = {
  OPEN: [TicketStatus.IN_PROGRESS, TicketStatus.RESOLVED],
  IN_PROGRESS: [TicketStatus.OPEN, TicketStatus.RESOLVED],
  RESOLVED: [TicketStatus.OPEN],
};

const TICKET_INCLUDE = { tenant: { select: { name: true } } } as const;

// Nil UUID: a valid value for the UUID columns that matches no row.
const NO_MATCH = '00000000-0000-0000-0000-000000000000';

@Injectable()
export class TicketsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly notificationsService: NotificationsService,
  ) {}

  // Tenant Admins and Analysts raise tickets. Recipients: every Admin of the
  // tenant (except the creator), plus every Integration Admin for MODULES.
  async create(user: AuthenticatedUser, dto: CreateTicketDto) {
    if (!user.tenantId) {
      throw new ForbiddenException('This account is not scoped to a tenant');
    }
    if ((dto.category === TicketCategory.MODULES) !== !!dto.moduleName) {
      throw new BadRequestException(
        dto.category === TicketCategory.MODULES
          ? 'moduleName is required for a Modules ticket'
          : 'moduleName is only allowed for a Modules ticket',
      );
    }

    const creator = await this.prisma.user.findUnique({
      where: { id: user.userId },
      select: { id: true, name: true, email: true, tenantId: true },
    });
    if (!creator || creator.tenantId !== user.tenantId) {
      throw new ForbiddenException('Account not found in this tenant');
    }

    const ticket = await this.prisma.ticket.create({
      data: {
        tenantId: user.tenantId,
        createdById: creator.id,
        createdByName: creator.name,
        createdByEmail: creator.email,
        title: dto.title,
        description: dto.description,
        category: dto.category,
        moduleName: dto.moduleName ?? null,
      },
      include: TICKET_INCLUDE,
    });

    const recipients = await this.prisma.user.findMany({
      where: {
        id: { not: creator.id },
        OR: [
          { tenantId: user.tenantId, role: UserRole.ADMIN },
          ...(dto.category === TicketCategory.MODULES
            ? [{ role: UserRole.INTEGRATION_ADMIN }]
            : []),
        ],
      },
      select: { id: true },
    });
    await this.notificationsService.notify(
      recipients.map((r) => r.id),
      ticket.id,
      NotificationType.TICKET_CREATED,
    );

    return ticket;
  }

  list(user: AuthenticatedUser, status?: TicketStatus) {
    return this.prisma.ticket.findMany({
      where: { ...this.visibleTo(user), ...(status ? { status } : {}) },
      include: TICKET_INCLUDE,
      orderBy: { createdAt: 'desc' },
      take: LIST_LIMIT,
    });
  }

  async findOne(user: AuthenticatedUser, id: string) {
    const ticket = await this.prisma.ticket.findFirst({
      where: { id, ...this.visibleTo(user) },
      include: TICKET_INCLUDE,
    });
    if (!ticket) {
      throw new NotFoundException('Ticket not found');
    }
    return ticket;
  }

  async updateStatus(
    user: AuthenticatedUser,
    id: string,
    status: TicketStatus,
  ) {
    const ticket = await this.findOne(user, id);
    if (ticket.status === status) {
      throw new ConflictException(`Ticket is already ${status}`);
    }

    if (this.canHandle(user, ticket)) {
      if (!HANDLER_TRANSITIONS[ticket.status].includes(status)) {
        throw new ConflictException(
          `Cannot move a ${ticket.status} ticket to ${status}`,
        );
      }
    } else if (ticket.createdById === user.userId) {
      // The creator can only withdraw their own ticket.
      if (status !== TicketStatus.RESOLVED) {
        throw new ForbiddenException(
          'You can only mark your own ticket as resolved',
        );
      }
    } else {
      throw new ForbiddenException('You cannot change this ticket');
    }

    const updated = await this.prisma.ticket.update({
      where: { id },
      data: { status, statusChangedById: user.userId },
      include: TICKET_INCLUDE,
    });

    if (ticket.createdById && ticket.createdById !== user.userId) {
      await this.notificationsService.notify(
        [ticket.createdById],
        id,
        NotificationType.TICKET_STATUS_CHANGED,
      );
    }

    return updated;
  }

  // Admin: every ticket in their tenant. Analyst: their own. Integration
  // Admin: MODULES tickets from every tenant. Anyone else: nothing.
  private visibleTo(user: AuthenticatedUser): Prisma.TicketWhereInput {
    switch (user.role) {
      case UserRole.ADMIN:
        return { tenantId: user.tenantId ?? NO_MATCH };
      case UserRole.ANALYST:
        return {
          tenantId: user.tenantId ?? NO_MATCH,
          createdById: user.userId,
        };
      case UserRole.INTEGRATION_ADMIN:
        return { category: TicketCategory.MODULES };
      default:
        return { id: NO_MATCH };
    }
  }

  private canHandle(user: AuthenticatedUser, ticket: Ticket): boolean {
    return (
      (user.role === UserRole.ADMIN && user.tenantId === ticket.tenantId) ||
      (user.role === UserRole.INTEGRATION_ADMIN &&
        ticket.category === TicketCategory.MODULES)
    );
  }
}
