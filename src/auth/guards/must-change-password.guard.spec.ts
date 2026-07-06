import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { MustChangePasswordGuard } from './must-change-password.guard';

describe('MustChangePasswordGuard', () => {
  let guard: MustChangePasswordGuard;
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
    guard = new MustChangePasswordGuard(reflector);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('allows access when the route is marked @SkipPasswordCheck()', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

    const result = guard.canActivate(
      buildContext({ userId: '1', mustChangePassword: true }),
    );

    expect(result).toBe(true);
  });

  it('allows access when there is no user on the request (public route)', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

    const result = guard.canActivate(buildContext(undefined));

    expect(result).toBe(true);
  });

  it('allows access when mustChangePassword is false', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

    const result = guard.canActivate(
      buildContext({ userId: '1', mustChangePassword: false }),
    );

    expect(result).toBe(true);
  });

  it('throws ForbiddenException when mustChangePassword is true and the route is not exempt', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

    expect(() =>
      guard.canActivate(
        buildContext({ userId: '1', mustChangePassword: true }),
      ),
    ).toThrow(ForbiddenException);
  });
});
