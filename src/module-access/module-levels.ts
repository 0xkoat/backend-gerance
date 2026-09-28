import { AnalystLevel, ModuleName } from '../generated/prisma/enums';

// Starting minimum analyst level per module when a Super Admin activates it for
// a tenant (the migration applied the same mapping to existing rows). The
// tenant's own Admin can change it afterwards.
export const DEFAULT_MIN_ANALYST_LEVEL: Record<ModuleName, AnalystLevel> = {
  CTI: AnalystLevel.L1,
  VM: AnalystLevel.L1,
  SIEM: AnalystLevel.L2,
  EDR: AnalystLevel.L2,
  SOAR: AnalystLevel.L3,
  DFIR: AnalystLevel.L3,
};

const LEVEL_RANK: Record<AnalystLevel, number> = { L1: 1, L2: 2, L3: 3 };

// L3 can launch anything L2 can, and so on.
export function meetsMinLevel(
  level: AnalystLevel,
  minLevel: AnalystLevel,
): boolean {
  return LEVEL_RANK[level] >= LEVEL_RANK[minLevel];
}
