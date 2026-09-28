-- DropForeignKey
ALTER TABLE "AssetFeedEntry" DROP CONSTRAINT "AssetFeedEntry_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "CtiIoc" DROP CONSTRAINT "CtiIoc_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "DfirIncident" DROP CONSTRAINT "DfirIncident_assignedToUserId_fkey";

-- DropForeignKey
ALTER TABLE "DfirIncident" DROP CONSTRAINT "DfirIncident_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "DfirLink" DROP CONSTRAINT "DfirLink_incidentId_fkey";

-- DropForeignKey
ALTER TABLE "EdrDetection" DROP CONSTRAINT "EdrDetection_assignedToUserId_fkey";

-- DropForeignKey
ALTER TABLE "EdrDetection" DROP CONSTRAINT "EdrDetection_endpointId_fkey";

-- DropForeignKey
ALTER TABLE "EdrDetection" DROP CONSTRAINT "EdrDetection_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "EdrEndpoint" DROP CONSTRAINT "EdrEndpoint_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "SiemAlert" DROP CONSTRAINT "SiemAlert_assignedToUserId_fkey";

-- DropForeignKey
ALTER TABLE "SiemAlert" DROP CONSTRAINT "SiemAlert_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "SiemLog" DROP CONSTRAINT "SiemLog_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "SoarExecution" DROP CONSTRAINT "SoarExecution_alertId_fkey";

-- DropForeignKey
ALTER TABLE "SoarExecution" DROP CONSTRAINT "SoarExecution_playbookId_fkey";

-- DropForeignKey
ALTER TABLE "SoarExecution" DROP CONSTRAINT "SoarExecution_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "SoarPlaybook" DROP CONSTRAINT "SoarPlaybook_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "VmAsset" DROP CONSTRAINT "VmAsset_tenantId_fkey";

-- DropForeignKey
ALTER TABLE "VmVulnerability" DROP CONSTRAINT "VmVulnerability_assetId_fkey";

-- DropForeignKey
ALTER TABLE "VmVulnerability" DROP CONSTRAINT "VmVulnerability_assignedToUserId_fkey";

-- DropForeignKey
ALTER TABLE "VmVulnerability" DROP CONSTRAINT "VmVulnerability_tenantId_fkey";

-- DropTable
DROP TABLE "AssetFeedEntry";

-- DropTable
DROP TABLE "CtiIoc";

-- DropTable
DROP TABLE "DfirIncident";

-- DropTable
DROP TABLE "DfirLink";

-- DropTable
DROP TABLE "EdrDetection";

-- DropTable
DROP TABLE "EdrEndpoint";

-- DropTable
DROP TABLE "SiemAlert";

-- DropTable
DROP TABLE "SiemLog";

-- DropTable
DROP TABLE "SoarExecution";

-- DropTable
DROP TABLE "SoarPlaybook";

-- DropTable
DROP TABLE "VmAsset";

-- DropTable
DROP TABLE "VmVulnerability";

-- DropEnum
DROP TYPE "CtiIocType";

-- DropEnum
DROP TYPE "DfirIncidentStatus";

-- DropEnum
DROP TYPE "DfirLinkSourceType";

-- DropEnum
DROP TYPE "EdrDetectionStatus";

-- DropEnum
DROP TYPE "EdrEndpointStatus";

-- DropEnum
DROP TYPE "Severity";

-- DropEnum
DROP TYPE "SiemAlertStatus";

-- DropEnum
DROP TYPE "SoarExecutionStatus";

-- DropEnum
DROP TYPE "VmVulnerabilitiesStatus";

