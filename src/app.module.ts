import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { TenantsModule } from './tenants/tenants.module';
import { HealthModule } from './health/health.module';
import { EventsModule } from './events/events.module';
import { ModuleAccessModule } from './module-access/module-access.module';
import { TicketsModule } from './tickets/tickets.module';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from './auth/guards/roles.guard';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { MustChangePasswordGuard } from './auth/guards/must-change-password.guard';
import { UserThrottlerGuard } from './common/user-throttler.guard';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ScheduleModule } from '@nestjs/schedule';

// Composition root for dependency injection (main.ts is the composition
// root for HTTP-level middleware/pipes — see its own header comment).
//
// providers order matters: NestJS applies multiple APP_GUARD entries in
// registration order, and each of these three guards depends on the
// previous one having already run (JwtAuthGuard populates request.user,
// which RolesGuard and MustChangePasswordGuard both read) — see each
// guard's own file for what it does. Don't reorder these three without
// re-reading all three guards' comments first.
//
// UserThrottlerGuard goes last: it counts authenticated requests per user,
// so it needs request.user from JwtAuthGuard. ThrottlerModule.forRoot's
// 120-per-60s is the app-wide default; AuthController (5/min), ticket
// creation and the module connection test override it with @Throttle(),
// and health checks opt out with @SkipThrottle().
@Module({
  imports: [
    UsersModule,
    AuthModule,
    TenantsModule,
    HealthModule,
    EventsModule,
    ModuleAccessModule,
    TicketsModule,
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 120 }]),
    EventEmitterModule.forRoot(),
    ScheduleModule.forRoot(),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    {
      provide: APP_GUARD,
      useClass: MustChangePasswordGuard,
    },
    // useExisting so tests can swap the guard with overrideProvider().
    UserThrottlerGuard,
    {
      provide: APP_GUARD,
      useExisting: UserThrottlerGuard,
    },
  ],
})
export class AppModule {}
