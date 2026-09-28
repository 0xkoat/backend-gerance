-- v2 roles: analyst levels, INTEGRATION_ADMIN, VIEWER removed.

-- CreateEnum
CREATE TYPE "AnalystLevel" AS ENUM ('L1', 'L2', 'L3');

-- AlterTable
ALTER TABLE "User" ADD COLUMN "analystLevel" "AnalystLevel";
ALTER TABLE "User" ALTER COLUMN "role" DROP DEFAULT;

-- Existing rows: VIEWER has no v2 equivalent, so viewers become the
-- lowest-access analyst level, and every existing analyst starts at L1 too.
-- Admins raise levels by hand afterwards; nobody silently gains access.
UPDATE "User" SET "role" = 'ANALYST' WHERE "role" = 'VIEWER';
UPDATE "User" SET "analystLevel" = 'L1' WHERE "role" = 'ANALYST';

-- AlterEnum (drop VIEWER, add INTEGRATION_ADMIN)
CREATE TYPE "UserRole_new" AS ENUM ('SUPER_ADMIN', 'INTEGRATION_ADMIN', 'ADMIN', 'ANALYST');
ALTER TABLE "User" ALTER COLUMN "role" TYPE "UserRole_new" USING ("role"::text::"UserRole_new");
ALTER TYPE "UserRole" RENAME TO "UserRole_old";
ALTER TYPE "UserRole_new" RENAME TO "UserRole";
DROP TYPE "UserRole_old";

-- Every analyst has a level, and only analysts have one.
ALTER TABLE "User" ADD CONSTRAINT "User_analystLevel_matches_role"
  CHECK (("role" = 'ANALYST') = ("analystLevel" IS NOT NULL));
