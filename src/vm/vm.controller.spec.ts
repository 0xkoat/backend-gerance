import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { VmController } from './vm.controller';
import { VmService } from './vm.service';
import {
  ModuleName,
  Severity,
  VmVulnerabilitiesStatus,
} from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UserRole } from '../generated/prisma/enums';
import { CreateVmAssetDto } from './dto/createVmAsset.dto';
import { UpdateVulnerabilityStatusDto } from './dto/updateVulnerabilityStatus.dto';
import { IngestVmEventDto } from './dto/ingestVmEvent.dto';
import { VmQueryDto } from './dto/vmQuery.dto';
import { AssignDto } from '../common/dto/assign.dto';

const mockVmService = {
  listAssets: jest.fn(),
  createAsset: jest.fn(),
  updateAsset: jest.fn(),
  deleteAsset: jest.fn(),
  query: jest.fn(),
  updateVulnerabilityStatus: jest.fn(),
  assignVulnerability: jest.fn(),
  unassignVulnerability: jest.fn(),
  ingest: jest.fn(),
};

describe('VmController', () => {
  let controller: VmController;

  const analyst: AuthenticatedUser = {
    userId: 'user-1',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const noTenantAdmin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
    tenantId: null,
    mustChangePassword: false,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [VmController],
      providers: [{ provide: VmService, useValue: mockVmService }],
    }).compile();

    controller = module.get<VmController>(VmController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('listAssets', () => {
    it('returns assets for the caller tenant', async () => {
      const assets = [{ id: 'asset-1', tenantId: 'tenant-1' }];
      mockVmService.listAssets.mockResolvedValue(assets);

      const result = await controller.listAssets(analyst);

      expect(result).toEqual(assets);
      expect(mockVmService.listAssets).toHaveBeenCalledWith('tenant-1');
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.listAssets(noTenantAdmin)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockVmService.listAssets).not.toHaveBeenCalled();
    });
  });

  describe('createAsset', () => {
    const dto: CreateVmAssetDto = {
      name: 'web-server-1',
      ip: '10.0.0.5',
      type: 'server',
    };

    it('creates an asset scoped to the caller tenant', async () => {
      const created = { id: 'asset-1', tenantId: 'tenant-1', ...dto };
      mockVmService.createAsset.mockResolvedValue(created);

      const result = await controller.createAsset(analyst, dto);

      expect(result).toEqual(created);
      expect(mockVmService.createAsset).toHaveBeenCalledWith('tenant-1', dto);
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.createAsset(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockVmService.createAsset).not.toHaveBeenCalled();
    });
  });

  describe('updateAsset', () => {
    it('passes the tenant and id to the service', async () => {
      const updated = { id: 'asset-1', tenantId: 'tenant-1' };
      mockVmService.updateAsset.mockResolvedValue(updated);

      const result = await controller.updateAsset(analyst, 'asset-1', {
        name: 'renamed',
      });

      expect(result).toEqual(updated);
      expect(mockVmService.updateAsset).toHaveBeenCalledWith(
        'tenant-1',
        'asset-1',
        { name: 'renamed' },
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateAsset(noTenantAdmin, 'asset-1', {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockVmService.updateAsset).not.toHaveBeenCalled();
    });
  });

  describe('deleteAsset', () => {
    it('passes the tenant and id to the service', async () => {
      mockVmService.deleteAsset.mockResolvedValue(undefined);

      await controller.deleteAsset(analyst, 'asset-1');

      expect(mockVmService.deleteAsset).toHaveBeenCalledWith(
        'tenant-1',
        'asset-1',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.deleteAsset(noTenantAdmin, 'asset-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockVmService.deleteAsset).not.toHaveBeenCalled();
    });
  });

  describe('queryVulnerabilities', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: VmQueryDto = {
        severity: Severity.HIGH,
        page: 1,
        pageSize: 20,
      };
      mockVmService.query.mockResolvedValue([]);

      await controller.queryVulnerabilities(analyst, query);

      expect(mockVmService.query).toHaveBeenCalledWith({
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.queryVulnerabilities(noTenantAdmin, {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockVmService.query).not.toHaveBeenCalled();
    });
  });

  describe('updateVulnerabilityStatus', () => {
    const dto: UpdateVulnerabilityStatusDto = {
      status: VmVulnerabilitiesStatus.REMEDIATED,
    };

    it('passes the raw status value, not the whole DTO, to the service', async () => {
      const updated = {
        id: 'vuln-1',
        status: VmVulnerabilitiesStatus.REMEDIATED,
      };
      mockVmService.updateVulnerabilityStatus.mockResolvedValue(updated);

      const result = await controller.updateVulnerabilityStatus(
        analyst,
        'vuln-1',
        dto,
      );

      expect(result).toEqual(updated);
      expect(mockVmService.updateVulnerabilityStatus).toHaveBeenCalledWith(
        'tenant-1',
        'vuln-1',
        VmVulnerabilitiesStatus.REMEDIATED,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateVulnerabilityStatus(noTenantAdmin, 'vuln-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockVmService.updateVulnerabilityStatus).not.toHaveBeenCalled();
    });
  });

  describe('assignVulnerability', () => {
    it('passes the caller and requested assignee to the service', async () => {
      const updated = { id: 'vuln-1', assignedToUserId: 'analyst-2' };
      mockVmService.assignVulnerability.mockResolvedValue(updated);

      const result = await controller.assignVulnerability(analyst, 'vuln-1', {
        assignedToUserId: 'analyst-2',
      });

      expect(result).toEqual(updated);
      expect(mockVmService.assignVulnerability).toHaveBeenCalledWith(
        'tenant-1',
        'vuln-1',
        analyst,
        'analyst-2',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      const dto: AssignDto = {};
      await expect(
        controller.assignVulnerability(noTenantAdmin, 'vuln-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockVmService.assignVulnerability).not.toHaveBeenCalled();
    });
  });

  describe('unassignVulnerability', () => {
    it('passes the caller to the service', async () => {
      const updated = { id: 'vuln-1', assignedToUserId: null };
      mockVmService.unassignVulnerability.mockResolvedValue(updated);

      const result = await controller.unassignVulnerability(analyst, 'vuln-1');

      expect(result).toEqual(updated);
      expect(mockVmService.unassignVulnerability).toHaveBeenCalledWith(
        'tenant-1',
        'vuln-1',
        analyst,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.unassignVulnerability(noTenantAdmin, 'vuln-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockVmService.unassignVulnerability).not.toHaveBeenCalled();
    });
  });

  describe('ingestEvent', () => {
    const dto: IngestVmEventDto = {
      assetIP: '10.0.0.5',
      assetName: 'web-server-1',
      assetType: 'server',
      description: 'Outdated OpenSSL version',
      cveId: 'CVE-2026-1234',
      severity: Severity.HIGH,
    };

    it('builds a UnifiedEvent with the asset/finding fields nested under data', async () => {
      mockVmService.ingest.mockResolvedValue(undefined);

      await controller.ingestEvent(analyst, dto);

      expect(mockVmService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.VM,
          type: 'vulnerability',
          severity: Severity.HIGH,
          data: {
            assetIP: '10.0.0.5',
            assetName: 'web-server-1',
            assetType: 'server',
            description: 'Outdated OpenSSL version',
            cveId: 'CVE-2026-1234',
          },
        }),
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.ingestEvent(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockVmService.ingest).not.toHaveBeenCalled();
    });
  });
});
