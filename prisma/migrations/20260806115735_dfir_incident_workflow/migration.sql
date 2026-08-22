-- AlterEnum
ALTER TYPE "DfirIncidentStatus" ADD VALUE 'ESCALATED';

-- AlterTable
ALTER TABLE "DfirIncident" ADD COLUMN     "assignedToUserId" UUID,
ADD COLUMN     "description" TEXT,
ADD COLUMN     "mitreTechniques" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- AddForeignKey
ALTER TABLE "DfirIncident" ADD CONSTRAINT "DfirIncident_assignedToUserId_fkey" FOREIGN KEY ("assignedToUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
