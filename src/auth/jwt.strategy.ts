import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';
import { AnalystLevel, UserRole } from 'src/generated/prisma/enums';

export interface JwtPayload {
  sub: string;
  role: UserRole;
  analystLevel: AnalystLevel | null;
  tenantId: string | null;
  mustChangePassword: boolean;
}

export interface AuthenticatedUser {
  userId: string;
  role: UserRole;
  analystLevel: AnalystLevel | null;
  tenantId: string | null;
  mustChangePassword: boolean;
}

// The one place access-token claims are built — shared by AuthService
// (login/refresh) and UsersController (post-password-change re-sign) so the
// two signing sites can't drift apart.
export function accessTokenClaims(user: {
  id: string;
  role: UserRole;
  analystLevel: AnalystLevel | null;
  tenantId: string | null;
  mustChangePassword: boolean;
}): JwtPayload {
  return {
    sub: user.id,
    role: user.role,
    analystLevel: user.analystLevel,
    tenantId: user.tenantId,
    mustChangePassword: user.mustChangePassword,
  };
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET environment variable is not defined');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  // Passport calls this after verifying the JWT's signature/expiry; whatever
  // it returns becomes request.user for the rest of the request (consumed by
  // RolesGuard, MustChangePasswordGuard, and every controller's @CurrentUser
  // decorator). Trusts the token's claims as-is, no DB lookup here, so a
  // role/tenantId change on the user's row doesn't take effect until their
  // access token expires (up to 15 minutes, per the short-lived-token design).
  // Not async — there's no DB lookup or other await here (see the comment
  // above), and Passport's own contract accepts a plain returned value
  // just as well as a Promise; `async` with nothing to await was flagged
  // by eslint's require-await rule for good reason.
  validate(payload: JwtPayload): AuthenticatedUser {
    return {
      userId: payload.sub,
      role: payload.role,
      // Tokens minted before analyst levels existed carry no claim at all.
      analystLevel: payload.analystLevel ?? null,
      tenantId: payload.tenantId,
      mustChangePassword: payload.mustChangePassword,
    };
  }
}
