import { Injectable, MessageEvent } from '@nestjs/common';
import { fromEvent, Observable, merge, filter, map } from 'rxjs';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type {
  UnifiedEvent,
  SoarExecutionPayload,
  DfirIncidentPayload,
} from '../common/security-module/types';

type StreamableEvent =
  UnifiedEvent | SoarExecutionPayload | DfirIncidentPayload;

@Injectable()
export class EventsService {
  constructor(private readonly eventEmitter: EventEmitter2) {}

  streamForTenant(tenantId: string): Observable<MessageEvent> {
    return merge(
      fromEvent(this.eventEmitter, 'edr.detection.created'),
      fromEvent(this.eventEmitter, 'siem.alert.created'),
      fromEvent(this.eventEmitter, 'soar.execution.created'),
      fromEvent(this.eventEmitter, 'dfir.incident.created'),
      fromEvent(this.eventEmitter, 'vm.vulnerability.created'),
      fromEvent(this.eventEmitter, 'cti.ioc.created'),
    ).pipe(
      map((event) => event as StreamableEvent),
      filter((event) => event.tenantId === tenantId),
      map((event) => ({ data: event })),
    );
  }
}
