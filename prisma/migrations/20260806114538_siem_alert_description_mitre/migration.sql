-- AlterTable
ALTER TABLE "SiemAlert" ADD COLUMN     "description" TEXT,
ADD COLUMN     "mitreTechniques" TEXT[] DEFAULT ARRAY[]::TEXT[];
