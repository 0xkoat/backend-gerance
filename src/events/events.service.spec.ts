import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { MessageEvent } from '@nestjs/common';
import { EventsService, NOTIFICATION_CREATED } from './events.service';

describe('EventsService', () => {
  let service: EventsService;
  let eventEmitter: EventEmitter2;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [EventsService, EventEmitter2],
    }).compile();

    service = module.get<EventsService>(EventsService);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
  });

  describe('streamForUser', () => {
    it('forwards a notification addressed to the caller', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForUser('user-1')
        .subscribe((message) => received.push(message));

      const event = { userId: 'user-1', notification: { id: 'n-1' } };
      eventEmitter.emit(NOTIFICATION_CREATED, event);
      subscription.unsubscribe();

      expect(received).toEqual([{ data: event }]);
    });

    it("never forwards another user's notification", () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForUser('user-1')
        .subscribe((message) => received.push(message));

      eventEmitter.emit(NOTIFICATION_CREATED, { userId: 'user-2' });
      subscription.unsubscribe();

      expect(received).toHaveLength(0);
    });

    it('ignores events outside the streamed list', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForUser('user-1')
        .subscribe((message) => received.push(message));

      eventEmitter.emit('something.else', { userId: 'user-1' });
      subscription.unsubscribe();

      expect(received).toHaveLength(0);
    });

    it('stays open and stops delivering once unsubscribed', () => {
      let completed = false;
      const received: MessageEvent[] = [];
      const subscription = service.streamForUser('user-1').subscribe({
        next: (message) => received.push(message),
        complete: () => (completed = true),
      });

      expect(completed).toBe(false);
      subscription.unsubscribe();
      eventEmitter.emit(NOTIFICATION_CREATED, { userId: 'user-1' });

      expect(received).toHaveLength(0);
    });
  });
});
