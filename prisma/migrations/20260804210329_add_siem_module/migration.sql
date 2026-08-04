-- CreateEnum
CREATE TYPE "SiemAlertStatus" AS ENUM ('OPEN', 'ASSIGNED', 'ESCALATED', 'RESOLVED');

-- CreateTable
CREATE TABLE "SiemLog" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "rawData" JSONB,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SiemLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SiemAlert" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" "SiemAlertStatus" NOT NULL DEFAULT 'OPEN',
    "assignedToUserId" UUID,
    "rawData" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SiemAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SiemLog_tenantId_idx" ON "SiemLog"("tenantId");

-- CreateIndex
CREATE INDEX "SiemAlert_tenantId_idx" ON "SiemAlert"("tenantId");

-- AddForeignKey
ALTER TABLE "SiemLog" ADD CONSTRAINT "SiemLog_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SiemAlert" ADD CONSTRAINT "SiemAlert_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SiemAlert" ADD CONSTRAINT "SiemAlert_assignedToUserId_fkey" FOREIGN KEY ("assignedToUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
