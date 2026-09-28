import { Injectable, NotFoundException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { NotificationType } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { NOTIFICATION_CREATED } from '../events/events.service';

const LIST_LIMIT = 30;

// What a notification carries to the UI: enough of its ticket to render a line.
const NOTIFICATION_INCLUDE = {
  ticket: {
    select: {
      id: true,
      title: true,
      category: true,
      moduleName: true,
      status: true,
    },
  },
} as const;

@Injectable()
export class NotificationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  // Stores one notification per recipient, then pushes each over the SSE
  // stream (EventsService relays notification.created to that user only).
  async notify(
    recipientIds: string[],
    ticketId: string,
    type: NotificationType,
  ): Promise<void> {
    const uniqueRecipients = [...new Set(recipientIds)];
    if (uniqueRecipients.length === 0) {
      return;
    }

    const created = await this.prisma.notification.createManyAndReturn({
      data: uniqueRecipients.map((userId) => ({ userId, ticketId, type })),
      include: NOTIFICATION_INCLUDE,
    });

    for (const notification of created) {
      this.eventEmitter.emit(NOTIFICATION_CREATED, {
        userId: notification.userId,
        notification,
      });
    }
  }

  async listForUser(userId: string) {
    const [notifications, unreadCount] = await this.prisma.$transaction([
      this.prisma.notification.findMany({
        where: { userId },
        include: NOTIFICATION_INCLUDE,
        orderBy: { createdAt: 'desc' },
        take: LIST_LIMIT,
      }),
      this.prisma.notification.count({ where: { userId, readAt: null } }),
    ]);
    return { notifications, unreadCount };
  }

  // Both mark-read calls return the caller's new unread count for the bell.
  async markRead(userId: string, id: string): Promise<{ unreadCount: number }> {
    // Scoped by userId, so one user can never mark another's notification.
    const { count } = await this.prisma.notification.updateMany({
      where: { id, userId, readAt: null },
      data: { readAt: new Date() },
    });
    if (count === 0) {
      const exists = await this.prisma.notification.findFirst({
        where: { id, userId },
        select: { id: true },
      });
      if (!exists) {
        throw new NotFoundException('Notification not found');
      }
    }
    return this.unreadCount(userId);
  }

  async markAllRead(userId: string): Promise<{ unreadCount: number }> {
    await this.prisma.notification.updateMany({
      where: { userId, readAt: null },
      data: { readAt: new Date() },
    });
    return { unreadCount: 0 };
  }

  private async unreadCount(userId: string): Promise<{ unreadCount: number }> {
    const unreadCount = await this.prisma.notification.count({
      where: { userId, readAt: null },
    });
    return { unreadCount };
  }
}
