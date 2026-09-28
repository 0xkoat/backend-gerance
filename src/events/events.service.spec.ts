import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { MessageEvent } from '@nestjs/common';
import { EventsService, STREAMED_EVENTS } from './events.service';

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

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('streamForTenant', () => {
    it('stays open when no event names are streamed', () => {
      let completed = false;
      const subscription = service
        .streamForTenant('tenant-1')
        .subscribe({ complete: () => (completed = true) });

      expect(STREAMED_EVENTS).toHaveLength(0);
      expect(completed).toBe(false);
      subscription.unsubscribe();
    });

    it('does not relay events outside the streamed list', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForTenant('tenant-1')
        .subscribe((message) => received.push(message));

      eventEmitter.emit('edr.detection.created', { tenantId: 'tenant-1' });
      subscription.unsubscribe();

      expect(received).toHaveLength(0);
    });
  });
});
