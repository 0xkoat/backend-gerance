-- CreateEnum
CREATE TYPE "EdrDetectionStatus" AS ENUM ('OPEN', 'ASSIGNED', 'ESCALATED', 'RESOLVED');

-- AlterTable
ALTER TABLE "EdrDetection" ADD COLUMN     "assignedToUserId" UUID,
ADD COLUMN     "description" TEXT,
ADD COLUMN     "mitreTechniques" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "status" "EdrDetectionStatus" NOT NULL DEFAULT 'OPEN';

-- AddForeignKey
ALTER TABLE "EdrDetection" ADD CONSTRAINT "EdrDetection_assignedToUserId_fkey" FOREIGN KEY ("assignedToUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
