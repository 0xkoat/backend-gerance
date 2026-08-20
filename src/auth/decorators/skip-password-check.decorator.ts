import { SetMetadata } from '@nestjs/common';

// Opt-out from MustChangePasswordGuard, for the handful of routes an
// account stuck in the mandatory first-login flow still needs to reach:
// logout, and the self-change route (PATCH /users/me/password) itself.
export const SKIP_PASSWORD_CHECK_KEY = 'skipPasswordCheck';
export const SkipPasswordCheck = () =>
  SetMetadata(SKIP_PASSWORD_CHECK_KEY, true);
