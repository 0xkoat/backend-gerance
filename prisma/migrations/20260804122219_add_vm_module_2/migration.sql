/*
  Warnings:

  - A unique constraint covering the columns `[tenantId,ip]` on the table `VmAsset` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "VmAsset_tenantId_ip_key" ON "VmAsset"("tenantId", "ip");
