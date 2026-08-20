import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { PrismaModule } from '../prisma/prisma.module';

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error('JWT_SECRET environment variable is not defined');
}

@Module({
  imports: [
    PrismaModule,
    JwtModule.register({
      secret: jwtSecret,
      // Matches AuthModule's access token lifetime (15m). This registration is used by
      // UsersController.changeMyPassword to re-sign a fresh access token right after the
      // mandatory first-login password change — it must not silently mint a longer-lived
      // token for that flow than login/refresh do. Found stale at 1h (pre-refresh-token-era
      // value) during the frontend's Phase 1 auth migration verification, 2026-08-07.
      signOptions: { expiresIn: '15m' },
    }),
  ],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
