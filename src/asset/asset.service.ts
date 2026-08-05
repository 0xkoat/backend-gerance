import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { ModuleName } from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import type {
  UnifiedEvent,
  SoarExecutionPayload,
  DfirIncidentPayload,
} from '../common/security-module/types';

@Injectable()
export class AssetService {
  constructor(private readonly prisma: PrismaService) {}

  @OnEvent('edr.detection.created')
  async handleEdrDetection(event: UnifiedEvent): Promise<void> {
    const data = event.data as { hostname: string; detectionName: string; detectionId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.EDR,
        type: 'detection',
        severity: event.severity,
        timestamp: event.timestamp,
        summary: `${data.detectionName} on ${data.hostname}`,
        sourceId: data.detectionId,
      },
    });
  }

  @OnEvent('siem.alert.created')
  async handleSiemAlert(event: UnifiedEvent): Promise<void> {
    const data = event.data as { title: string; alertId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.SIEM,
        type: 'alert',
        severity: event.severity,
        timestamp: event.timestamp,
        summary: data.title,
        sourceId: data.alertId,
      },
    });
  }

  @OnEvent('soar.execution.created')
  async handleSoarExecution(payload: SoarExecutionPayload): Promise<void> {
    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: payload.tenantId,
        source: ModuleName.SOAR,
        type: 'execution',
        severity: payload.severity,
        timestamp: payload.timestamp,
        summary: `Playbook "${payload.playbookName}" executed`,
        sourceId: payload.executionId,
      },
    });
  }

  @OnEvent('vm.vulnerability.created')
  async handleVmVulnerability(event: UnifiedEvent): Promise<void> {
    const data = event.data as { description: string; vulnerabilityId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.VM,
        type: 'vulnerability',
        severity: event.severity,
        timestamp: event.timestamp,
        summary: data.description,
        sourceId: data.vulnerabilityId,
      },
    });
  }

  @OnEvent('cti.ioc.created')
  async handleCtiIoc(event: UnifiedEvent): Promise<void> {
    const data = event.data as { type: string; value: string; iocId: string };

    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: event.tenantId,
        source: ModuleName.CTI,
        type: 'ioc',
        severity: event.severity,
        timestamp: event.timestamp,
        summary: `${data.type} IOC: ${data.value}`,
        sourceId: data.iocId,
      },
    });
  }

  @OnEvent('dfir.incident.created')
  async handleDfirIncident(payload: DfirIncidentPayload): Promise<void> {
    await this.prisma.assetFeedEntry.create({
      data: {
        tenantId: payload.tenantId,
        source: ModuleName.DFIR,
        type: 'incident',
        severity: payload.severity,
        timestamp: payload.timestamp,
        summary: payload.title,
        sourceId: payload.incidentId,
      },
    });
  }
}
