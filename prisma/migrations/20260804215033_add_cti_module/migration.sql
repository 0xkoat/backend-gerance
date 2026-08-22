-- CreateEnum
CREATE TYPE "CtiIocType" AS ENUM ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL');

-- CreateTable
CREATE TABLE "CtiIoc" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "type" "CtiIocType" NOT NULL,
    "value" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL,
    "source" TEXT NOT NULL,
    "rawData" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CtiIoc_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CtiIoc_tenantId_idx" ON "CtiIoc"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "CtiIoc_tenantId_type_value_key" ON "CtiIoc"("tenantId", "type", "value");

-- AddForeignKey
ALTER TABLE "CtiIoc" ADD CONSTRAINT "CtiIoc_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
