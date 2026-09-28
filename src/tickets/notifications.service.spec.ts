import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { NotificationsService } from './notifications.service';
import { PrismaService } from '../prisma/prisma.service';
import { NotificationType } from '../generated/prisma/client';
import { NOTIFICATION_CREATED } from '../events/events.service';

const mockPrismaService = {
  notification: {
    createManyAndReturn: jest.fn(),
    findMany: jest.fn(),
    findFirst: jest.fn(),
    count: jest.fn(),
    updateMany: jest.fn(),
  },
  $transaction: jest.fn(),
};
const mockEventEmitter = { emit: jest.fn() };

describe('NotificationsService', () => {
  let service: NotificationsService;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NotificationsService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get(NotificationsService);
  });

  describe('notify', () => {
    it('stores one row per distinct recipient and pushes each live', async () => {
      const created = [
        { id: 'n-1', userId: 'admin-1' },
        { id: 'n-2', userId: 'ia-1' },
      ];
      mockPrismaService.notification.createManyAndReturn.mockResolvedValue(
        created,
      );

      await service.notify(
        ['admin-1', 'ia-1', 'admin-1'],
        'ticket-1',
        NotificationType.TICKET_CREATED,
      );

      expect(
        mockPrismaService.notification.createManyAndReturn,
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          data: [
            {
              userId: 'admin-1',
              ticketId: 'ticket-1',
              type: NotificationType.TICKET_CREATED,
            },
            {
              userId: 'ia-1',
              ticketId: 'ticket-1',
              type: NotificationType.TICKET_CREATED,
            },
          ],
        }),
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(NOTIFICATION_CREATED, {
        userId: 'admin-1',
        notification: created[0],
      });
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(NOTIFICATION_CREATED, {
        userId: 'ia-1',
        notification: created[1],
      });
    });

    it('does nothing when there is no recipient', async () => {
      await service.notify([], 'ticket-1', NotificationType.TICKET_CREATED);

      expect(
        mockPrismaService.notification.createManyAndReturn,
      ).not.toHaveBeenCalled();
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });
  });

  it("lists the caller's latest notifications with the unread count", async () => {
    mockPrismaService.$transaction.mockResolvedValue([[{ id: 'n-1' }], 3]);

    await expect(service.listForUser('user-1')).resolves.toEqual({
      notifications: [{ id: 'n-1' }],
      unreadCount: 3,
    });
  });

  describe('markRead', () => {
    it("only ever touches the caller's own notification", async () => {
      mockPrismaService.notification.updateMany.mockResolvedValue({ count: 1 });
      mockPrismaService.notification.count.mockResolvedValue(4);

      await expect(service.markRead('user-1', 'n-1')).resolves.toEqual({
        unreadCount: 4,
      });

      expect(mockPrismaService.notification.updateMany).toHaveBeenCalledWith({
        where: { id: 'n-1', userId: 'user-1', readAt: null },
        data: { readAt: expect.any(Date) },
      });
    });

    it('is a no-op for an already-read notification', async () => {
      mockPrismaService.notification.updateMany.mockResolvedValue({ count: 0 });
      mockPrismaService.notification.findFirst.mockResolvedValue({ id: 'n-1' });
      mockPrismaService.notification.count.mockResolvedValue(0);

      await expect(service.markRead('user-1', 'n-1')).resolves.toEqual({
        unreadCount: 0,
      });
    });

    it("404s someone else's (or a missing) notification", async () => {
      mockPrismaService.notification.updateMany.mockResolvedValue({ count: 0 });
      mockPrismaService.notification.findFirst.mockResolvedValue(null);

      await expect(service.markRead('user-1', 'n-9')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  it('marks all of the caller’s unread notifications as read', async () => {
    mockPrismaService.notification.updateMany.mockResolvedValue({ count: 2 });

    await expect(service.markAllRead('user-1')).resolves.toEqual({
      unreadCount: 0,
    });

    expect(mockPrismaService.notification.updateMany).toHaveBeenCalledWith({
      where: { userId: 'user-1', readAt: null },
      data: { readAt: expect.any(Date) },
    });
  });
});
