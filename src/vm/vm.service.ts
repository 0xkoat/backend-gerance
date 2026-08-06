import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Prisma, VmVulnerability, VmAsset } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityModule } from '../common/security-module/security-module.interface';
import { ModuleName, VmVulnerabilitiesStatus } from '../generated/prisma/enums';
import {
  BaseQueryFilters,
  ModuleHealth,
  UnifiedEvent,
} from '../common/security-module/types';
import {
  resolveAssignee,
  assertCanTransitionStatus,
} from '../common/assignment';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

export interface VmQueryFilters extends BaseQueryFilters {
  assetId?: string;
  status?: VmVulnerabilitiesStatus;
}

@Injectable()
export class VmService implements SecurityModule<
  VmVulnerability,
  VmQueryFilters
> {
  private readonly logger = new Logger(VmService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

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
      create: {
        tenantId: event.tenantId,
        name: data.assetName,
        ip: data.assetIP,
        type: data.assetType,
      },
    });

    const vulnerability = await this.prisma.vmVulnerability.create({
      data: {
        tenantId: event.tenantId,
        assetId: asset.id,
        description: data.description,
        cveId: data.cveId,
        severity: event.severity,
        rawData: event.data as Prisma.InputJsonValue,
      },
    });

    this.eventEmitter.emit('vm.vulnerability.created', {
      ...event,
      data: { ...event.data, vulnerabilityId: vulnerability.id },
    });
  }

  async query(filters: VmQueryFilters): Promise<VmVulnerability[]> {
    const {
      tenantId,
      severity,
      assignedToUserId,
      dateFrom,
      dateTo,
      page = 1,
      pageSize = 20,
      assetId,
      status,
    } = filters;

    const where: Prisma.VmVulnerabilityWhereInput = {
      tenantId,
      ...(severity && { severity }),
      ...(assetId && { assetId }),
      ...(status && { status }),
      ...(assignedToUserId && { assignedToUserId }),
      ...((dateFrom || dateTo) && {
        createdAt: {
          ...(dateFrom && { gte: dateFrom }),
          ...(dateTo && { lte: dateTo }),
        },
      }),
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
      return {
        module: ModuleName.VM,
        status: 'ok',
        lastIngestion: latest?.createdAt,
      };
    } catch (error) {
      this.logger.error('VM health check failed', error);
      return { module: ModuleName.VM, status: 'down' };
    }
  }

  async listAssets(tenantId: string): Promise<VmAsset[]> {
    return this.prisma.vmAsset.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'asc' },
    });
  }

  async createAsset(
    tenantId: string,
    dto: { name: string; ip: string; type: string },
  ): Promise<VmAsset> {
    return this.prisma.vmAsset.create({
      data: {
        tenantId,
        name: dto.name,
        ip: dto.ip,
        type: dto.type,
      },
    });
  }

  async updateAsset(
    tenantId: string,
    id: string,
    dto: { name?: string; ip?: string; type?: string },
  ): Promise<VmAsset> {
    const asset = await this.prisma.vmAsset.findUnique({ where: { id } });
    if (!asset || asset.tenantId !== tenantId) {
      throw new NotFoundException('Asset not found');
    }

    return this.prisma.vmAsset.update({ where: { id }, data: dto });
  }

  // VmVulnerability.assetId RESTRICTs on this table, so a hard delete is
  // only allowed once no vulnerability references it — same guard shape as
  // SoarService.deletePlaybook and EdrService.deleteEndpoint. Unlike
  // EdrEndpoint, VmAsset has no status/lifecycle field to fall back to —
  // remediating or accepting-risk on the associated vulnerabilities first
  // is the only path to freeing an asset up for deletion.
  async deleteAsset(tenantId: string, id: string): Promise<void> {
    const asset = await this.prisma.vmAsset.findUnique({ where: { id } });
    if (!asset || asset.tenantId !== tenantId) {
      throw new NotFoundException('Asset not found');
    }

    const vulnerabilityCount = await this.prisma.vmVulnerability.count({
      where: { assetId: id },
    });
    if (vulnerabilityCount > 0) {
      throw new ConflictException(
        'Cannot delete an asset that has associated vulnerabilities',
      );
    }

    await this.prisma.vmAsset.delete({ where: { id } });
  }

  async updateVulnerabilityStatus(
    tenantId: string,
    id: string,
    status: VmVulnerabilitiesStatus,
  ): Promise<VmVulnerability> {
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

  async assignVulnerability(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
    requestedAssigneeId: string | undefined,
  ): Promise<VmVulnerability> {
    const vulnerability = await this.prisma.vmVulnerability.findUnique({
      where: { id },
    });
    if (!vulnerability || vulnerability.tenantId !== tenantId) {
      throw new NotFoundException('Vulnerability not found');
    }

    const assigneeId = await resolveAssignee(
      this.prisma,
      caller,
      tenantId,
      requestedAssigneeId,
    );

    const updated = await this.prisma.vmVulnerability.update({
      where: { id },
      data: { assignedToUserId: assigneeId },
    });

    // Assignment doesn't move VmVulnerability's own remediation status (see
    // the module-scope decision in CLAUDE.md) — the emitted status is just
    // whatever the record's current remediation status already was.
    this.eventEmitter.emit('vm.vulnerability.assigned', {
      tenantId,
      source: ModuleName.VM,
      recordId: updated.id,
      assignedToUserId: assigneeId,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }

  // No status to revert here (assignment never touched it) — just clears
  // the assignee. Still gated by assertCanTransitionStatus: only the
  // current assignee or an Admin can hand it back.
  async unassignVulnerability(
    tenantId: string,
    id: string,
    caller: AuthenticatedUser,
  ): Promise<VmVulnerability> {
    const vulnerability = await this.prisma.vmVulnerability.findUnique({
      where: { id },
    });
    if (!vulnerability || vulnerability.tenantId !== tenantId) {
      throw new NotFoundException('Vulnerability not found');
    }

    assertCanTransitionStatus(caller, vulnerability.assignedToUserId);

    if (!vulnerability.assignedToUserId) {
      throw new ConflictException('Vulnerability is not currently assigned');
    }

    const updated = await this.prisma.vmVulnerability.update({
      where: { id },
      data: { assignedToUserId: null },
    });

    this.eventEmitter.emit('vm.vulnerability.unassigned', {
      tenantId,
      source: ModuleName.VM,
      recordId: updated.id,
      status: updated.status,
      timestamp: new Date(),
    });

    return updated;
  }
}
