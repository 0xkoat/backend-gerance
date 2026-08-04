import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, VmVulnerability, VmAsset } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import { ModuleName, VmVulnerabilitiesStatus } from '../generated/prisma/enums';
import { BaseQueryFilters, ModuleHealth, UnifiedEvent } from '../common/security-module/types';

export interface VmQueryFilters extends BaseQueryFilters { 
    assetId?: string;
    status?: VmVulnerabilitiesStatus;
}

@Injectable()
export class VmService implements SecurityModule<VmVulnerability, VmQueryFilters> {
    constructor(private readonly prisma: PrismaService) { }
    
    async ingest(event: UnifiedEvent): Promise<void> {
        
        const data = event.data as {
            assetIP: string;
            assetName: string;
            assetType: string;
            description: string;
            cveId?: string;
        };

        const asset = await this.prisma.vmAsset.upsert({
            where: { tenantId_ip: { tenantId: event.tenantId, ip: data.assetIP } },
            update: {},
            create: { tenantId: event.tenantId, name: data.assetName, ip: data.assetIP, type: data.assetType },

        })

        await this.prisma.vmVulnerability.create({
            data: {
                tenantId: event.tenantId,
                assetId: asset.id,
                description: data.description,
                cveId: data.cveId,
                severity: event.severity,
                rawData: event.data as Prisma.InputJsonValue,
            },
        });
    }

    async query(filters: VmQueryFilters): Promise<VmVulnerability[]> {
        const { tenantId, severity, dateFrom, dateTo, page = 1, pageSize = 20, assetId, status } = filters;
        
        const where: Prisma.VmVulnerabilityWhereInput = {
            tenantId,
            ...(severity && { severity }),
            ...(assetId && { assetId }),
            ...(status && { status }),
            ...(dateFrom || dateTo) && {
                createdAt: {
                    ...(dateFrom && { gte: dateFrom }),
                    ...(dateTo && { lte: dateTo }),
                },
            },
        };

        return this.prisma.vmVulnerability.findMany({
            where,
            skip: (page - 1) * pageSize,
            take: pageSize,
            orderBy: { createdAt: 'desc' },
        });
    }

    async healthCheck(): Promise<ModuleHealth> { 
        try {
            const latest = await this.prisma.vmVulnerability.findFirst({
                orderBy: { createdAt: 'desc' },
                select: { createdAt: true },
            });
            return { module: ModuleName.VM, status: 'ok', lastIngestion: latest?.createdAt };
        } catch {
            return { module: ModuleName.VM, status: 'down' };
        }
    }

    async listAssets(tenantId: string): Promise<VmAsset[]> {
        return this.prisma.vmAsset.findMany({
            where: { tenantId },
            orderBy: { createdAt: 'asc' },
        });
    }

    async createAsset(tenantId: string, dto: { name: string; ip: string; type: string }): Promise<VmAsset> {
        return this.prisma.vmAsset.create({
            data: {
                tenantId,
                name: dto.name,
                ip: dto.ip,
                type: dto.type,
            },
        });
    }

    async updateVulnerabilityStatus(tenantId: string, id:string, status: VmVulnerabilitiesStatus): Promise<VmVulnerability> {
        const vulnerability = await this.prisma.vmVulnerability.findUnique({
            where: { id },
        });

        if (!vulnerability || vulnerability.tenantId !== tenantId) {
            throw new NotFoundException('Vulnerability not found');
        }

        return this.prisma.vmVulnerability.update({
            where: { id },
            data: { status },
        });
    }

}

