import { MockAdapter } from './mock-adapter';
import { ModuleDataSourceAdapter } from '../common/security-module/data-source-adapter.interface';
import { ModuleName } from '../generated/prisma/enums';

describe('MockAdapter', () => {
  // Typed as the interface, not the concrete class — these tests exercise
  // the full ModuleDataSourceAdapter contract (config/since included), not
  // just whatever narrower signature MockAdapter itself happens to declare.
  let adapter: ModuleDataSourceAdapter;

  beforeEach(() => {
    adapter = new MockAdapter();
  });

  it('returns exactly one record for any module', async () => {
    const records = await adapter.fetchSince(ModuleName.EDR, {});
    expect(records).toHaveLength(1);
  });

  it.each([
    [ModuleName.VM, 'vulnerability'],
    [ModuleName.EDR, 'detection'],
    [ModuleName.SIEM, 'event'],
    [ModuleName.CTI, 'ioc'],
    [ModuleName.SOAR, 'event'],
    [ModuleName.DFIR, 'event'],
  ])('returns a %s-shaped record for %s', async (moduleName, expectedType) => {
    const [record] = await adapter.fetchSince(moduleName, {});
    expect(record.type).toBe(expectedType);
    expect(record.timestamp).toBeInstanceOf(Date);
    expect(record.data).toBeDefined();
  });

  it('ignores config and since (mock data is always the same canned record)', async () => {
    const withoutSince = await adapter.fetchSince(ModuleName.VM, {});
    const withSince = await adapter.fetchSince(
      ModuleName.VM,
      { apiKey: 'secret' },
      new Date('2026-01-01'),
    );
    expect(withoutSince[0].data).toEqual(withSince[0].data);
  });
});
