// Demo tenants and users for local dev, for multiple tenants. Deliberately
// NOT wired into `prisma db seed` (that stays scoped to the one-time Super
// Admin bootstrap in seed.ts) — this is an explicit, opt-in dev action:
// `npm run seed:demo`.
import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import { faker } from '@faker-js/faker';
import { PrismaClient } from '../src/generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import {
  AnalystLevel,
  UserRole,
  ModuleName,
} from '../src/generated/prisma/enums';

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});

const TENANT_COUNT = 5;
const SHARED_PASSWORD = 'DemoPassw0rd!2026';
// Fixed, not faker-generated, and seeded after the tenants so adding it
// doesn't shift any tenant's generated identities.
const DEMO_INTEGRATION_ADMIN_EMAIL = 'integration.admin@secops.demo';

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

interface SeedCredential {
  tenantName: string;
  email: string;
  role: UserRole;
  analystLevel: AnalystLevel | null;
}

const usedEmails = new Set<string>();

function uniqueEmail(tenantSlug: string, role: string): string {
  let email: string;
  do {
    email = faker.internet
      .email({
        firstName: faker.person.firstName(),
        lastName: faker.person.lastName(),
        provider: `${tenantSlug}.demo`,
      })
      .toLowerCase();
  } while (usedEmails.has(email));
  usedEmails.add(email);
  return email;
}

function phoneNumber(): string {
  return `+216${randomInt(20000000, 59999999)}`;
}

async function seedTenant(
  index: number,
  hashedPassword: string,
): Promise<SeedCredential[]> {
  const tenantName = `${faker.company.name()} ${faker.company.buzzNoun()}`;
  const tenantSlug = faker.helpers
    .slugify(tenantName)
    .toLowerCase()
    .slice(0, 20);
  const tenant = await prisma.tenant.create({ data: { name: tenantName } });

  const credentials: SeedCredential[] = [];

  // ---- Users: 1 first Admin, 1 co-Admin, one Analyst per level.
  const userRows: Array<{
    id: string;
    email: string;
    phoneNumber: string;
    name: string;
    role: UserRole;
    analystLevel: AnalystLevel | null;
    hashedPassword: string;
    tenantId: string;
    mustChangePassword: boolean;
  }> = [];

  function addUser(role: UserRole, analystLevel: AnalystLevel | null = null) {
    const email = uniqueEmail(tenantSlug, role.toLowerCase());
    const id = randomUUID();
    userRows.push({
      id,
      email,
      phoneNumber: phoneNumber(),
      name: faker.person.fullName(),
      role,
      analystLevel,
      hashedPassword,
      tenantId: tenant.id,
      // Seed-script bootstrap, same precedent as the Super Admin seed in
      // seed.ts — not the API path the mustChangePassword hard rule targets.
      mustChangePassword: false,
    });
    credentials.push({ tenantName, email, role, analystLevel });
  }

  addUser(UserRole.ADMIN);
  addUser(UserRole.ADMIN);
  for (const level of Object.values(AnalystLevel)) {
    addUser(UserRole.ANALYST, level);
  }

  await prisma.user.createMany({ data: userRows });

  // ---- TenantModule: one row per module, all active.
  await prisma.tenantModule.createMany({
    data: Object.values(ModuleName).map((moduleName) => ({
      id: randomUUID(),
      tenantId: tenant.id,
      moduleName,
      isActive: true,
      config: {},
    })),
  });

  console.log(`  Tenant "${tenantName}": ${userRows.length} users`);

  return credentials;
}

async function main() {
  // Fixed seed: makes the faker-generated tenant/company names and person
  // names (and therefore emails, since those derive from the person name)
  // reproducible run over run — added 2026-08-19 so the new Playwright e2e
  // suite (frontend/e2e/fixtures/accounts.ts) can hardcode real seeded
  // identities instead of scraping them from the UI at runtime. Phone
  // numbers still vary per run (`randomInt` uses Math.random, not faker).
  faker.seed(20260819);
  console.log(`Seeding ${TENANT_COUNT} demo tenants...\n`);
  const hashedPassword = await argon2.hash(SHARED_PASSWORD);

  const allCredentials: SeedCredential[] = [];
  for (let i = 0; i < TENANT_COUNT; i++) {
    const creds = await seedTenant(i, hashedPassword);
    allCredentials.push(...creds);
  }

  // Platform-wide, like the Super Admin: no tenant.
  await prisma.user.create({
    data: {
      email: DEMO_INTEGRATION_ADMIN_EMAIL,
      phoneNumber: phoneNumber(),
      name: 'Demo Integration Admin',
      role: UserRole.INTEGRATION_ADMIN,
      hashedPassword,
      mustChangePassword: false,
    },
  });
  allCredentials.push({
    tenantName: 'Platform (no tenant)',
    email: DEMO_INTEGRATION_ADMIN_EMAIL,
    role: UserRole.INTEGRATION_ADMIN,
    analystLevel: null,
  });

  console.log('\n=== Demo credentials (all accounts share one password) ===');
  console.log(`Password for every seeded account: ${SHARED_PASSWORD}\n`);

  let currentTenant = '';
  for (const cred of allCredentials) {
    if (cred.tenantName !== currentTenant) {
      currentTenant = cred.tenantName;
      console.log(`\n${currentTenant}`);
    }
    const label = cred.analystLevel
      ? `${cred.role} ${cred.analystLevel}`
      : cred.role;
    console.log(`  [${label.padEnd(17)}] ${cred.email}`);
  }
  console.log(`\nTotal accounts seeded: ${allCredentials.length}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
