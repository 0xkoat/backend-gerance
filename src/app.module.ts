import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { TenantsModule } from './tenants/tenants.module';
import { HealthModule } from './health/health.module';
import { VmModule } from './vm/vm.module';
import { EdrModule } from './edr/edr.module';
import { SiemModule } from './siem/siem.module';
import { CtiModule } from './cti/cti.module';
import { SoarModule } from './soar/soar.module';
import { DfirModule } from './dfir/dfir.module';
import { AssetModule } from './asset/asset.module';
import { EventsModule } from './events/events.module';
import { PollingModule } from './polling/polling.module';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from './auth/guards/roles.guard';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { MustChangePasswordGuard } from './auth/guards/must-change-password.guard';
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
// ThrottlerModule.forRoot's 10-per-60s here is the app-wide default; only
// AuthController overrides it with the tighter 5-per-60s login/refresh/
// logout/forgot-password limit (see that controller's own @Throttle()).
@Module({
  imports: [
    UsersModule,
    AuthModule,
    TenantsModule,
    HealthModule,
    VmModule,
    EdrModule,
    SiemModule,
    CtiModule,
    SoarModule,
    DfirModule,
    AssetModule,
    EventsModule,
    PollingModule,
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }]),
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
  ],
})
export class AppModule {}
