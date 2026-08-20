import { SetMetadata } from '@nestjs/common';

// The only opt-out from JwtAuthGuard's default "every route requires a
// valid access token" — see jwt-auth.guard.ts. Used sparingly: login,
// refresh, forgot-password, and GET /health.
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
