import { Injectable, MessageEvent } from '@nestjs/common';
import { fromEvent, Observable, merge, filter, map, NEVER } from 'rxjs';
import { EventEmitter2 } from '@nestjs/event-emitter';

// Every event relayed over SSE names the one user it is for.
export interface UserScopedEvent {
  userId: string;
}

// Explicit event-name list (not EventEmitterModule's wildcard mode) so every
// streamed name is reviewable in one place.
export const NOTIFICATION_CREATED = 'notification.created';
export const STREAMED_EVENTS: readonly string[] = [NOTIFICATION_CREATED];

@Injectable()
export class EventsService {
  constructor(private readonly eventEmitter: EventEmitter2) {}

  // One SSE stream per open connection, filtered to the caller's own user id —
  // per user rather than per tenant, since platform-wide Integration Admins
  // (no tenant) receive notifications too. This filter is the only isolation
  // boundary here: EventEmitter2 itself is process-global. NEVER keeps the
  // stream open between events. fromEvent's Node-style overload untyped + cast
  // right after the merge, since RxJS 7's typed overload for
  // EventEmitter2-shaped emitters is deprecated.
  streamForUser(userId: string): Observable<MessageEvent> {
    return merge(
      NEVER,
      ...STREAMED_EVENTS.map((name) => fromEvent(this.eventEmitter, name)),
    ).pipe(
      map((event) => event as UserScopedEvent),
      filter((event) => event.userId === userId),
      map((event) => ({ data: event })),
    );
  }
}
