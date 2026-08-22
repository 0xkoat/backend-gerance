import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from './roles.guard';
import { UserRole } from '../../generated/prisma/enums';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  const buildContext = (user?: unknown): ExecutionContext => {
    const request = { user };
    return {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('allows access when the route has no @Roles() metadata', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

    const result = guard.canActivate(buildContext({ role: UserRole.VIEWER }));

    expect(result).toBe(true);
  });

  it('allows access when the user role is in the required list', () => {
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockReturnValue([UserRole.ADMIN]);

    const result = guard.canActivate(
      buildContext({ userId: '1', role: UserRole.ADMIN, tenantId: 't1' }),
    );

    expect(result).toBe(true);
  });

  it('denies access when the user role is not in the required list', () => {
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockReturnValue([UserRole.ADMIN]);

    const result = guard.canActivate(
      buildContext({ userId: '1', role: UserRole.VIEWER, tenantId: 't1' }),
    );

    expect(result).toBe(false);
  });

  it('accepts any role listed when multiple roles are allowed', () => {
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockReturnValue([UserRole.ADMIN, UserRole.ANALYST]);

    const result = guard.canActivate(
      buildContext({ userId: '1', role: UserRole.ANALYST, tenantId: 't1' }),
    );

    expect(result).toBe(true);
  });

  it('throws UnauthorizedException when roles are required but there is no user on the request', () => {
    jest
      .spyOn(reflector, 'getAllAndOverride')
      .mockReturnValue([UserRole.ADMIN]);

    expect(() => guard.canActivate(buildContext(undefined))).toThrow(
      UnauthorizedException,
    );
  });
});
