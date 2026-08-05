-- CreateTable
CREATE TABLE "AssetFeedEntry" (
    "id" UUID NOT NULL,
    "tenantId" UUID NOT NULL,
    "source" "ModuleName" NOT NULL,
    "type" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "summary" TEXT NOT NULL,
    "sourceId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AssetFeedEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AssetFeedEntry_tenantId_timestamp_idx" ON "AssetFeedEntry"("tenantId", "timestamp");

-- AddForeignKey
ALTER TABLE "AssetFeedEntry" ADD CONSTRAINT "AssetFeedEntry_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
