import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let reflector: Reflector;
  let superCanActivateSpy: jest.SpyInstance;

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
    guard = new JwtAuthGuard(reflector);

    // JwtAuthGuard.prototype.canActivate is our override; the mixin class
    // produced by AuthGuard('jwt') sits one level up the prototype chain.
    superCanActivateSpy = jest.spyOn(
      Object.getPrototypeOf(Object.getPrototypeOf(guard)),
      'canActivate',
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('allows access without invoking the jwt strategy when the route is @Public()', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

    const result = await guard.canActivate(buildContext());

    expect(result).toBe(true);
    expect(superCanActivateSpy).not.toHaveBeenCalled();
  });

  it('delegates to the jwt strategy when the route is not public', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
    superCanActivateSpy.mockResolvedValue(true);
    const context = buildContext({
      userId: '1',
      role: 'ADMIN',
      tenantId: 't1',
    });

    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(superCanActivateSpy).toHaveBeenCalledWith(context);
  });

  it('throws UnauthorizedException when the jwt strategy rejects the request', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
    superCanActivateSpy.mockResolvedValue(false);

    await expect(guard.canActivate(buildContext())).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('throws UnauthorizedException if no user ends up on the request', async () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
    superCanActivateSpy.mockResolvedValue(true);

    await expect(guard.canActivate(buildContext(undefined))).rejects.toThrow(
      UnauthorizedException,
    );
  });
});
