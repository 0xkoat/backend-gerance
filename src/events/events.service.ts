import { Injectable, MessageEvent } from '@nestjs/common';
import { fromEvent, Observable, merge, filter, map } from 'rxjs';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type {
  UnifiedEvent,
  SoarExecutionPayload,
  DfirIncidentPayload,
  RecordAssignedPayload,
  RecordStatusChangedPayload,
  RecordDeletedPayload,
} from '../common/security-module/types';

type StreamableEvent =
  | UnifiedEvent
  | SoarExecutionPayload
  | DfirIncidentPayload
  | RecordAssignedPayload
  | RecordStatusChangedPayload
  | RecordDeletedPayload;

@Injectable()
export class EventsService {
  constructor(private readonly eventEmitter: EventEmitter2) {}

  // One SSE stream per open connection, filtered to the caller's own tenant.
  // This is the only tenant-isolation boundary here, since EventEmitter2
  // itself is process-global and not tenant-aware. Explicit event-name list
  // (not EventEmitterModule's wildcard mode) so every subscribed name is
  // reviewable in one place; fromEvent's Node-style overload untyped +
  // cast right after the merge, since RxJS 7's typed overload for
  // EventEmitter2-shaped emitters is deprecated.
  streamForTenant(tenantId: string): Observable<MessageEvent> {
    return merge(
      fromEvent(this.eventEmitter, 'edr.detection.created'),
      fromEvent(this.eventEmitter, 'siem.alert.created'),
      fromEvent(this.eventEmitter, 'soar.execution.created'),
      fromEvent(this.eventEmitter, 'dfir.incident.created'),
      fromEvent(this.eventEmitter, 'vm.vulnerability.created'),
      fromEvent(this.eventEmitter, 'cti.ioc.created'),
      fromEvent(this.eventEmitter, 'siem.alert.assigned'),
      fromEvent(this.eventEmitter, 'siem.alert.status_changed'),
      fromEvent(this.eventEmitter, 'edr.detection.assigned'),
      fromEvent(this.eventEmitter, 'edr.detection.status_changed'),
      fromEvent(this.eventEmitter, 'dfir.incident.assigned'),
      fromEvent(this.eventEmitter, 'dfir.incident.status_changed'),
      fromEvent(this.eventEmitter, 'vm.vulnerability.assigned'),
      fromEvent(this.eventEmitter, 'siem.alert.unassigned'),
      fromEvent(this.eventEmitter, 'edr.detection.unassigned'),
      fromEvent(this.eventEmitter, 'dfir.incident.unassigned'),
      fromEvent(this.eventEmitter, 'vm.vulnerability.unassigned'),
      fromEvent(this.eventEmitter, 'cti.ioc.deleted'),
    ).pipe(
      map((event) => event as StreamableEvent),
      filter((event) => event.tenantId === tenantId),
      map((event) => ({ data: event })),
    );
  }
}
