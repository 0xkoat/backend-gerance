import { UserThrottlerGuard } from './user-throttler.guard';

// getTracker is protected; exposed here only to test the key it builds.
class TestableGuard extends UserThrottlerGuard {
  tracker(req: Record<string, any>) {
    return this.getTracker(req);
  }
}

describe('UserThrottlerGuard', () => {
  const guard = new TestableGuard({ throttlers: [] }, {} as never, {} as never);

  it('counts authenticated requests per user, whatever the address', async () => {
    await expect(
      guard.tracker({ user: { userId: 'user-1' }, ip: '127.0.0.1' }),
    ).resolves.toBe('user:user-1');
  });

  it('counts anonymous requests per client address', async () => {
    await expect(guard.tracker({ ip: '203.0.113.7' })).resolves.toBe(
      'ip:203.0.113.7',
    );
  });
});
