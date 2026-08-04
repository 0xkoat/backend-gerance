-- CreateEnum
CREATE TYPE "SoarExecutionStatus" AS ENUM ('PENDING', 'RUNNING', 'SUCCESS', 'FAILED');

-- CreateTable
CREATE TABLE "SoarPlaybook" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "triggerCondition" JSONB NOT NULL,
    "actions" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SoarPlaybook_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SoarExecution" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "playbookId" UUID NOT NULL,
    "alertId" UUID NOT NULL,
    "status" "SoarExecutionStatus" NOT NULL DEFAULT 'PENDING',
    "logs" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SoarExecution_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SoarPlaybook_tenantId_idx" ON "SoarPlaybook"("tenantId");

-- CreateIndex
CREATE INDEX "SoarExecution_tenantId_idx" ON "SoarExecution"("tenantId");

-- AddForeignKey
ALTER TABLE "SoarPlaybook" ADD CONSTRAINT "SoarPlaybook_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoarExecution" ADD CONSTRAINT "SoarExecution_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoarExecution" ADD CONSTRAINT "SoarExecution_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "SoarPlaybook"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SoarExecution" ADD CONSTRAINT "SoarExecution_alertId_fkey" FOREIGN KEY ("alertId") REFERENCES "SiemAlert"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
