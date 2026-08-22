import { Controller, Sse, MessageEvent } from '@nestjs/common';
import { Observable } from 'rxjs';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { EventsService } from './events.service';
import { requireTenantId } from '../common/require-tenant-id';

@Controller('events')
export class EventsController {
  constructor(private readonly eventsService: EventsService) {}

  @Sse('stream')
  stream(@CurrentUser() user: AuthenticatedUser): Observable<MessageEvent> {
    const tenantId = requireTenantId(user);
    return this.eventsService.streamForTenant(tenantId);
  }
}
