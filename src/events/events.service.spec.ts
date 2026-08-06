import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { MessageEvent } from '@nestjs/common';
import { EventsService } from './events.service';
import { ModuleName, Severity } from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';

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
    const event: UnifiedEvent = {
      tenantId: 'tenant-1',
      timestamp: new Date(),
      source: ModuleName.EDR,
      type: 'detection',
      severity: Severity.HIGH,
      data: { hostname: 'web-server-1' },
    };

    it('forwards an event that belongs to the requested tenant', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForTenant('tenant-1')
        .subscribe((message) => received.push(message));

      eventEmitter.emit('edr.detection.created', event);
      subscription.unsubscribe();

      expect(received).toEqual([{ data: event }]);
    });

    it('filters out an event that belongs to a different tenant', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForTenant('tenant-1')
        .subscribe((message) => received.push(message));

      eventEmitter.emit('edr.detection.created', {
        ...event,
        tenantId: 'tenant-2',
      });
      subscription.unsubscribe();

      expect(received).toHaveLength(0);
    });

    it('forwards events from every subscribed event name for the matching tenant', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForTenant('tenant-1')
        .subscribe((message) => received.push(message));

      const eventNames = [
        'edr.detection.created',
        'siem.alert.created',
        'soar.execution.created',
        'dfir.incident.created',
        'vm.vulnerability.created',
        'cti.ioc.created',
        'siem.alert.assigned',
        'siem.alert.status_changed',
        'edr.detection.assigned',
        'edr.detection.status_changed',
        'dfir.incident.assigned',
        'dfir.incident.status_changed',
        'vm.vulnerability.assigned',
        'siem.alert.unassigned',
        'edr.detection.unassigned',
        'dfir.incident.unassigned',
        'vm.vulnerability.unassigned',
        'cti.ioc.deleted',
      ];
      eventNames.forEach((name) =>
        eventEmitter.emit(name, { tenantId: 'tenant-1' }),
      );
      subscription.unsubscribe();

      expect(received).toHaveLength(eventNames.length);
    });

    it('stops receiving events once unsubscribed', () => {
      const received: MessageEvent[] = [];
      const subscription = service
        .streamForTenant('tenant-1')
        .subscribe((message) => received.push(message));

      subscription.unsubscribe();
      eventEmitter.emit('edr.detection.created', event);

      expect(received).toHaveLength(0);
    });
  });
});
