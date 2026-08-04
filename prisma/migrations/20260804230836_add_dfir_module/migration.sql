-- CreateEnum
CREATE TYPE "DfirIncidentStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED');

-- CreateEnum
CREATE TYPE "DfirLinkSourceType" AS ENUM ('SIEM_ALERT', 'SIEM_LOG', 'EDR_DETECTION', 'VM_VULNERABILITY', 'CTI_IOC', 'SOAR_EXECUTION');

-- CreateTable
CREATE TABLE "DfirIncident" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" "DfirIncidentStatus" NOT NULL DEFAULT 'OPEN',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DfirIncident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DfirLink" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "incidentId" UUID NOT NULL,
    "sourceType" "DfirLinkSourceType" NOT NULL,
    "sourceId" UUID NOT NULL,

    CONSTRAINT "DfirLink_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DfirIncident_tenantId_idx" ON "DfirIncident"("tenantId");

-- CreateIndex
CREATE INDEX "DfirLink_tenantId_idx" ON "DfirLink"("tenantId");

-- CreateIndex
CREATE INDEX "DfirLink_incidentId_idx" ON "DfirLink"("incidentId");

-- AddForeignKey
ALTER TABLE "DfirIncident" ADD CONSTRAINT "DfirIncident_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DfirLink" ADD CONSTRAINT "DfirLink_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "DfirIncident"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
