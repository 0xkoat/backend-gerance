import { Test, TestingModule } from '@nestjs/testing';
import { AssetService } from './asset.service';
import { PrismaService } from '../prisma/prisma.service';
import { ModuleName, Severity } from '../generated/prisma/enums';
import { UnifiedEvent } from '../common/security-module/types';

const mockPrismaService = {
  assetFeedEntry: {
    create: jest.fn(),
  },
};

describe('AssetService', () => {
  let service: AssetService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AssetService,
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<AssetService>(AssetService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('handleEdrDetection', () => {
    it('writes an AssetFeedEntry projecting the EDR detection into the shared shape', async () => {
      const timestamp = new Date('2026-08-05T10:00:00Z');
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp,
        source: ModuleName.EDR,
        type: 'detection',
        severity: Severity.HIGH,
        data: {
          hostname: 'web-server-1',
          detectionName: 'Suspicious PowerShell execution chain',
          detectionId: 'detection-1',
        },
      };

      await service.handleEdrDetection(event);

      expect(mockPrismaService.assetFeedEntry.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.EDR,
          type: 'detection',
          severity: Severity.HIGH,
          timestamp,
          summary: 'Suspicious PowerShell execution chain on web-server-1',
          sourceId: 'detection-1',
        },
      });
    });
  });

  describe('handleSiemAlert', () => {
    it('writes an AssetFeedEntry projecting the SIEM alert into the shared shape', async () => {
      const timestamp = new Date('2026-08-05T10:05:00Z');
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp,
        source: ModuleName.SIEM,
        type: 'alert',
        severity: Severity.HIGH,
        data: {
          title: 'Suspicious PowerShell execution chain on web-server-1',
          alertId: 'alert-1',
        },
      };

      await service.handleSiemAlert(event);

      expect(mockPrismaService.assetFeedEntry.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.SIEM,
          type: 'alert',
          severity: Severity.HIGH,
          timestamp,
          summary: 'Suspicious PowerShell execution chain on web-server-1',
          sourceId: 'alert-1',
        },
      });
    });
  });

  describe('handleSoarExecution', () => {
    it('writes an AssetFeedEntry projecting the SOAR execution into the shared shape', async () => {
      const timestamp = new Date('2026-08-05T10:10:00Z');

      await service.handleSoarExecution({
        tenantId: 'tenant-1',
        executionId: 'execution-1',
        alertId: 'alert-1',
        playbookId: 'playbook-1',
        playbookName: 'Isolate host on critical alert',
        severity: Severity.CRITICAL,
        timestamp,
      });

      expect(mockPrismaService.assetFeedEntry.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.SOAR,
          type: 'execution',
          severity: Severity.CRITICAL,
          timestamp,
          summary: 'Playbook "Isolate host on critical alert" executed',
          sourceId: 'execution-1',
        },
      });
    });
  });

  describe('handleVmVulnerability', () => {
    it('writes an AssetFeedEntry projecting the VM vulnerability into the shared shape', async () => {
      const timestamp = new Date('2026-08-05T10:15:00Z');
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp,
        source: ModuleName.VM,
        type: 'vulnerability',
        severity: Severity.MEDIUM,
        data: {
          assetIP: '10.0.0.5',
          description: 'Outdated OpenSSL version',
          vulnerabilityId: 'vuln-1',
        },
      };

      await service.handleVmVulnerability(event);

      expect(mockPrismaService.assetFeedEntry.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.VM,
          type: 'vulnerability',
          severity: Severity.MEDIUM,
          timestamp,
          summary: 'Outdated OpenSSL version',
          sourceId: 'vuln-1',
        },
      });
    });
  });

  describe('handleCtiIoc', () => {
    it('writes an AssetFeedEntry projecting the CTI IOC into the shared shape', async () => {
      const timestamp = new Date('2026-08-05T10:20:00Z');
      const event: UnifiedEvent = {
        tenantId: 'tenant-1',
        timestamp,
        source: ModuleName.CTI,
        type: 'ioc',
        severity: Severity.LOW,
        data: {
          type: 'IP',
          value: '185.220.101.47',
          confidence: 85,
          source: 'AlienVault OTX',
          iocId: 'ioc-1',
        },
      };

      await service.handleCtiIoc(event);

      expect(mockPrismaService.assetFeedEntry.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.CTI,
          type: 'ioc',
          severity: Severity.LOW,
          timestamp,
          summary: 'IP IOC: 185.220.101.47',
          sourceId: 'ioc-1',
        },
      });
    });
  });

  describe('handleDfirIncident', () => {
    it('writes an AssetFeedEntry projecting the DFIR incident into the shared shape', async () => {
      const timestamp = new Date('2026-08-05T10:25:00Z');

      await service.handleDfirIncident({
        tenantId: 'tenant-1',
        incidentId: 'incident-1',
        title: 'Incident: Outbound C2 beaconing',
        severity: Severity.CRITICAL,
        timestamp,
      });

      expect(mockPrismaService.assetFeedEntry.create).toHaveBeenCalledWith({
        data: {
          tenantId: 'tenant-1',
          source: ModuleName.DFIR,
          type: 'incident',
          severity: Severity.CRITICAL,
          timestamp,
          summary: 'Incident: Outbound C2 beaconing',
          sourceId: 'incident-1',
        },
      });
    });
  });
});
