-- CreateIndex
CREATE INDEX "AssetFeedEntry_tenantId_source_sourceId_idx" ON "AssetFeedEntry"("tenantId", "source", "sourceId");
