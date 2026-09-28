import { buildModuleUrl } from './module-url';
import { DEFAULT_MIN_ANALYST_LEVEL, meetsMinLevel } from './module-levels';
import { AnalystLevel, ModuleProtocol } from '../generated/prisma/enums';

describe('buildModuleUrl', () => {
  it('builds protocol://host:port/path', () => {
    expect(
      buildModuleUrl({
        protocol: ModuleProtocol.HTTPS,
        host: '10.0.0.5',
        port: 5601,
        path: '/app/login',
      }),
    ).toBe('https://10.0.0.5:5601/app/login');
  });

  it('brackets an IPv6 host', () => {
    expect(
      buildModuleUrl({
        protocol: ModuleProtocol.HTTP,
        host: 'fd00::5',
        port: 8080,
        path: '/',
      }),
    ).toBe('http://[fd00::5]:8080/');
  });

  it('returns null while host or port is unset', () => {
    expect(
      buildModuleUrl({
        protocol: ModuleProtocol.HTTPS,
        host: null,
        port: null,
        path: '/',
      }),
    ).toBeNull();
    expect(
      buildModuleUrl({
        protocol: ModuleProtocol.HTTPS,
        host: '10.0.0.5',
        port: null,
        path: '/',
      }),
    ).toBeNull();
  });
});

describe('meetsMinLevel', () => {
  it.each([
    [AnalystLevel.L1, AnalystLevel.L1, true],
    [AnalystLevel.L1, AnalystLevel.L2, false],
    [AnalystLevel.L2, AnalystLevel.L1, true],
    [AnalystLevel.L2, AnalystLevel.L3, false],
    [AnalystLevel.L3, AnalystLevel.L3, true],
    [AnalystLevel.L3, AnalystLevel.L1, true],
  ])('%s against minimum %s -> %s', (level, min, expected) => {
    expect(meetsMinLevel(level, min)).toBe(expected);
  });
});

describe('DEFAULT_MIN_ANALYST_LEVEL', () => {
  it('matches the agreed mapping (L1: CTI, VM; L2: SIEM, EDR; L3: SOAR, DFIR)', () => {
    expect(DEFAULT_MIN_ANALYST_LEVEL).toEqual({
      CTI: 'L1',
      VM: 'L1',
      SIEM: 'L2',
      EDR: 'L2',
      SOAR: 'L3',
      DFIR: 'L3',
    });
  });
});
