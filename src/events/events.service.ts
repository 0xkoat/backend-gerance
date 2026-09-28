import { Injectable, MessageEvent } from '@nestjs/common';
import { fromEvent, Observable, merge, filter, map, NEVER } from 'rxjs';
import { EventEmitter2 } from '@nestjs/event-emitter';

// Every event relayed over SSE must carry the tenant it belongs to.
interface TenantScopedEvent {
  tenantId: string;
}

// Explicit event-name list (not EventEmitterModule's wildcard mode) so every
// streamed name is reviewable in one place. Empty since the security-module
// data layer was removed (v2 redesign) — ticket notifications are the next
// thing meant to be relayed here.
export const STREAMED_EVENTS: readonly string[] = [];

@Injectable()
export class EventsService {
  constructor(private readonly eventEmitter: EventEmitter2) {}

  // One SSE stream per open connection, filtered to the caller's own tenant.
  // This is the only tenant-isolation boundary here, since EventEmitter2
  // itself is process-global and not tenant-aware. NEVER keeps the stream
  // open even with no subscribed names — an empty merge() would complete
  // immediately and make every client's EventSource reconnect in a loop.
  // fromEvent's Node-style overload untyped + cast right after the merge,
  // since RxJS 7's typed overload for EventEmitter2-shaped emitters is
  // deprecated.
  streamForTenant(tenantId: string): Observable<MessageEvent> {
    return merge(
      NEVER,
      ...STREAMED_EVENTS.map((name) => fromEvent(this.eventEmitter, name)),
    ).pipe(
      map((event) => event as TenantScopedEvent),
      filter((event) => event.tenantId === tenantId),
      map((event) => ({ data: event })),
    );
  }
}
