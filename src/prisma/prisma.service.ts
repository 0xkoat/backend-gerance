import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client';

// Injectable wrapper around the generated PrismaClient — every service in
// the app depends on this instead of instantiating PrismaClient directly,
// so there's exactly one connection pool for the whole process. Uses the
// @prisma/adapter-pg driver adapter (Prisma 7) rather than Prisma's default
// query engine — see docs/internship-report-backend.md §4.1 for why, and
// note this changes how some errors surface (e.g. FK violations raise a
// DriverAdapterError, not a PrismaClientKnownRequestError — see
// SoarService.deletePlaybook's own comment for a real case this bit).
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
    });
  }

  // Connects eagerly at app startup rather than lazily on first query, so a
  // bad DATABASE_URL fails fast during boot instead of on some arbitrary
  // later request.
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
