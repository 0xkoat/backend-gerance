-- CreateEnum
CREATE TYPE "VmVulnerabilitiesStatus" AS ENUM ('OPEN', 'REMEDIATED', 'ACCEPTED_RISK');

-- CreateTable
CREATE TABLE "VmAsset" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VmAsset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VmVulnerability" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "assetId" UUID NOT NULL,
    "severity" "Severity" NOT NULL,
    "description" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "cveId" TEXT,
    "status" "VmVulnerabilitiesStatus" NOT NULL DEFAULT 'OPEN',
    "rawData" JSONB,

    CONSTRAINT "VmVulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "VmAsset_tenantId_idx" ON "VmAsset"("tenantId");

-- CreateIndex
CREATE INDEX "VmVulnerability_tenantId_idx" ON "VmVulnerability"("tenantId");

-- AddForeignKey
ALTER TABLE "VmAsset" ADD CONSTRAINT "VmAsset_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VmVulnerability" ADD CONSTRAINT "VmVulnerability_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VmVulnerability" ADD CONSTRAINT "VmVulnerability_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "VmAsset"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
