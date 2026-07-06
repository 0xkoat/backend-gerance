import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Injectable } from "@nestjs/common";
import { UserRole } from "src/generated/prisma/enums";


interface JwtPayload {
  sub: string;
  role: UserRole;
  tenantId: string | null;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error("JWT_SECRET environment variable is not defined");
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  async validate(payload: JwtPayload): Promise<{ userId: string; role: UserRole; tenantId: string | null }> {
    return { userId: payload.sub, role: payload.role, tenantId: payload.tenantId };
  }
}