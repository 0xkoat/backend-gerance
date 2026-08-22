/*
  Warnings:

  - You are about to drop the column `sourceType` on the `TenantModule` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "TenantModule" DROP COLUMN "sourceType";

-- DropEnum
DROP TYPE "ModuleSourceType";
