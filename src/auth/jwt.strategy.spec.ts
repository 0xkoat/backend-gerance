import {
  JwtStrategy,
  accessTokenClaims,
  type JwtPayload,
} from './jwt.strategy';
import { AnalystLevel, UserRole } from '../generated/prisma/enums';

describe('accessTokenClaims', () => {
  it('maps a user row to the access-token payload', () => {
    expect(
      accessTokenClaims({
        id: 'user-1',
        role: UserRole.ANALYST,
        analystLevel: AnalystLevel.L2,
        tenantId: 'tenant-1',
        mustChangePassword: false,
      }),
    ).toEqual({
      sub: 'user-1',
      role: UserRole.ANALYST,
      analystLevel: AnalystLevel.L2,
      tenantId: 'tenant-1',
      mustChangePassword: false,
    });
  });
});

describe('JwtStrategy.validate', () => {
  const originalSecret = process.env.JWT_SECRET;
  let strategy: JwtStrategy;

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret';
    strategy = new JwtStrategy();
  });

  afterAll(() => {
    process.env.JWT_SECRET = originalSecret;
  });

  it('carries analystLevel through to request.user', () => {
    const payload: JwtPayload = {
      sub: 'user-1',
      role: UserRole.ANALYST,
      analystLevel: AnalystLevel.L3,
      tenantId: 'tenant-1',
      mustChangePassword: false,
    };

    expect(strategy.validate(payload)).toEqual({
      userId: 'user-1',
      role: UserRole.ANALYST,
      analystLevel: AnalystLevel.L3,
      tenantId: 'tenant-1',
      mustChangePassword: false,
    });
  });

  it('treats a token minted before analyst levels existed as having no level', () => {
    const legacyPayload = {
      sub: 'user-1',
      role: UserRole.ADMIN,
      tenantId: 'tenant-1',
      mustChangePassword: false,
    } as unknown as JwtPayload;

    expect(strategy.validate(legacyPayload).analystLevel).toBeNull();
  });
});
