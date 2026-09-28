import { Controller, Sse, MessageEvent } from '@nestjs/common';
import { Observable } from 'rxjs';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { EventsService } from './events.service';

@Controller('events')
export class EventsController {
  constructor(private readonly eventsService: EventsService) {}

  // Any authenticated user, including the tenant-less Integration Admin.
  @Sse('stream')
  stream(@CurrentUser() user: AuthenticatedUser): Observable<MessageEvent> {
    return this.eventsService.streamForUser(user.userId);
  }
}
