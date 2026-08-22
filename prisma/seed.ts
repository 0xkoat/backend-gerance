import * as fs from 'node:fs';
import * as path from 'node:path';
import { PrismaClient, UserRole } from '../src/generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import * as argon2 from 'argon2';

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});

interface SuperAdminSeedEntry {
  email: string;
  password: string;
  name: string;
  phoneNumber: string;
}

function loadSuperAdmins(): SuperAdminSeedEntry[] {
  const filePath = path.join(__dirname, 'seed-data.json');

  if (!fs.existsSync(filePath)) {
    throw new Error(`Seed data file not found at ${filePath}`);
  }

  const entries = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as SuperAdminSeedEntry[];

  for (const entry of entries) {
    if (!entry.email || !entry.password || !entry.name || !entry.phoneNumber) {
      throw new Error(
        `Each entry in seed-data.json must have email, password, name and phoneNumber. Invalid entry: ${JSON.stringify(entry)}`,
      );
    }
  }

  return entries;
}

async function createSuperAdmin(entry: SuperAdminSeedEntry) {
  const existingUser = await prisma.user.findUnique({
    where: { email: entry.email },
  });

  if (existingUser) {
    console.log(`User with email ${entry.email} already exists, skipping.`);
    return;
  }

  const hashedPassword = await argon2.hash(entry.password);

  await prisma.user.create({
    data: {
      email: entry.email,
      hashedPassword,
      phoneNumber: entry.phoneNumber,
      name: entry.name,
      role: UserRole.SUPER_ADMIN,
      tenantId: null,
    },
  });

  console.log(`Super admin ${entry.email} created successfully.`);
}

async function main() {
  const superAdmins = loadSuperAdmins();

  for (const entry of superAdmins) {
    await createSuperAdmin(entry);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
