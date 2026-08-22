-- CreateEnum
CREATE TYPE "EdrEndpointStatus" AS ENUM ('ONLINE', 'OFFLINE', 'UNKNOWN');

-- CreateTable
CREATE TABLE "EdrEndpoint" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "hostname" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "os" TEXT NOT NULL,
    "status" "EdrEndpointStatus" NOT NULL DEFAULT 'UNKNOWN',
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EdrEndpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EdrDetection" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "endpointId" UUID NOT NULL,
    "detectionName" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "rawData" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EdrDetection_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "EdrEndpoint_tenantId_idx" ON "EdrEndpoint"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "EdrEndpoint_tenantId_hostname_key" ON "EdrEndpoint"("tenantId", "hostname");

-- CreateIndex
CREATE INDEX "EdrDetection_tenantId_idx" ON "EdrDetection"("tenantId");

-- AddForeignKey
ALTER TABLE "EdrEndpoint" ADD CONSTRAINT "EdrEndpoint_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EdrDetection" ADD CONSTRAINT "EdrDetection_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EdrDetection" ADD CONSTRAINT "EdrDetection_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "EdrEndpoint"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
