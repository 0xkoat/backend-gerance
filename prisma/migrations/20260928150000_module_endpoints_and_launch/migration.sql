-- v2 Phase 3: platform-wide module endpoints, per-tenant analyst level, launch audit.

-- CreateEnum
CREATE TYPE "ModuleProtocol" AS ENUM ('HTTP', 'HTTPS');

-- AlterTable: config was the free-form per-tenant integration blob of the
-- removed data layer; the minimum analyst level replaces it.
ALTER TABLE "TenantModule" DROP COLUMN "config",
ADD COLUMN "minAnalystLevel" "AnalystLevel" NOT NULL DEFAULT 'L1';

-- Existing subscriptions get the default mapping (L1: CTI, VM; L2: SIEM,
-- EDR; L3: SOAR, DFIR), same as TenantsService.activateModule.
UPDATE "TenantModule" SET "minAnalystLevel" = 'L2' WHERE "moduleName" IN ('SIEM', 'EDR');
UPDATE "TenantModule" SET "minAnalystLevel" = 'L3' WHERE "moduleName" IN ('SOAR', 'DFIR');

-- CreateTable
CREATE TABLE "ModuleEndpoint" (
    "moduleName" "ModuleName" NOT NULL,
    "protocol" "ModuleProtocol" NOT NULL DEFAULT 'HTTPS',
    "host" TEXT,
    "port" INTEGER,
    "path" TEXT NOT NULL DEFAULT '/',
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "updatedById" UUID,

    CONSTRAINT "ModuleEndpoint_pkey" PRIMARY KEY ("moduleName")
);

-- CreateTable
CREATE TABLE "ModuleLaunch" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "userEmail" TEXT NOT NULL,
    "role" "UserRole" NOT NULL,
    "tenantId" UUID NOT NULL,
    "moduleName" "ModuleName" NOT NULL,
    "targetUrl" TEXT NOT NULL,
    "launchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ModuleLaunch_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ModuleLaunch_tenantId_launchedAt_idx" ON "ModuleLaunch"("tenantId", "launchedAt");

-- One endpoint row per module, unconfigured (host/port NULL) until an
-- Integration Admin fills it in.
INSERT INTO "ModuleEndpoint" ("moduleName", "updatedAt") VALUES
    ('SIEM', CURRENT_TIMESTAMP),
    ('SOAR', CURRENT_TIMESTAMP),
    ('CTI', CURRENT_TIMESTAMP),
    ('EDR', CURRENT_TIMESTAMP),
    ('DFIR', CURRENT_TIMESTAMP),
    ('VM', CURRENT_TIMESTAMP);

-- Belt and braces for the DTO's own range check.
ALTER TABLE "ModuleEndpoint" ADD CONSTRAINT "ModuleEndpoint_port_range"
    CHECK ("port" IS NULL OR "port" BETWEEN 1 AND 65535);
