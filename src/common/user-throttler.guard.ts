import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

// App-wide rate limit, registered as the last APP_GUARD so JwtAuthGuard has
// already set request.user. Authenticated requests are counted per user, so
// one account can't eat another's budget even when every request reaches the
// backend from the same frontend (BFF) address. Anonymous routes (login,
// refresh, forgot-password) fall back to req.ip, which is the real client
// address only because main.ts sets Express's `trust proxy` and the BFF
// forwards X-Forwarded-For.
@Injectable()
export class UserThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, any>): Promise<string> {
    const user = req.user as AuthenticatedUser | undefined;
    return Promise.resolve(user ? `user:${user.userId}` : `ip:${req.ip}`);
  }
}
