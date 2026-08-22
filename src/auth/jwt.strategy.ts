import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable } from '@nestjs/common';
import { UserRole } from 'src/generated/prisma/enums';

interface JwtPayload {
  sub: string;
  role: UserRole;
  tenantId: string | null;
  mustChangePassword: boolean;
}

export interface AuthenticatedUser {
  userId: string;
  role: UserRole;
  tenantId: string | null;
  mustChangePassword: boolean;
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
      tenantId: payload.tenantId,
      mustChangePassword: payload.mustChangePassword,
    };
  }
}
