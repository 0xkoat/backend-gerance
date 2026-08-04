import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { DfirController } from './dfir.controller';
import { DfirService } from './dfir.service';
import {
  DfirIncidentStatus,
  DfirLinkSourceType,
  Severity,
  UserRole,
} from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { UpdateDfirIncidentStatusDto } from './dto/updateDfirIncidentStatus.dto';
import { CreateDfirLinkDto } from './dto/createDfirLink.dto';
import { DfirQueryDto } from './dto/dfirQuery.dto';

const mockDfirService = {
  query: jest.fn(),
  getIncidentDetail: jest.fn(),
  updateStatus: jest.fn(),
  linkRecord: jest.fn(),
};

describe('DfirController', () => {
  let controller: DfirController;

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
      controllers: [DfirController],
      providers: [{ provide: DfirService, useValue: mockDfirService }],
    }).compile();

    controller = module.get<DfirController>(DfirController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('queryIncidents', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: DfirQueryDto = {
        severity: Severity.HIGH,
        page: 1,
        pageSize: 20,
      };
      mockDfirService.query.mockResolvedValue([]);

      await controller.queryIncidents(analyst, query);

      expect(mockDfirService.query).toHaveBeenCalledWith({
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.queryIncidents(noTenantAdmin, {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockDfirService.query).not.toHaveBeenCalled();
    });
  });

  describe('getIncidentDetail', () => {
    it('returns the incident detail for the caller tenant', async () => {
      const incident = { id: 'incident-1', tenantId: 'tenant-1', links: [] };
      mockDfirService.getIncidentDetail.mockResolvedValue(incident);

      const result = await controller.getIncidentDetail(analyst, 'incident-1');

      expect(result).toEqual(incident);
      expect(mockDfirService.getIncidentDetail).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.getIncidentDetail(noTenantAdmin, 'incident-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockDfirService.getIncidentDetail).not.toHaveBeenCalled();
    });
  });

  describe('updateStatus', () => {
    const dto: UpdateDfirIncidentStatusDto = {
      status: DfirIncidentStatus.RESOLVED,
    };

    it('updates the status via the service', async () => {
      const updated = { id: 'incident-1', status: DfirIncidentStatus.RESOLVED };
      mockDfirService.updateStatus.mockResolvedValue(updated);

      const result = await controller.updateStatus(analyst, 'incident-1', dto);

      expect(result).toEqual(updated);
      expect(mockDfirService.updateStatus).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        DfirIncidentStatus.RESOLVED,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateStatus(noTenantAdmin, 'incident-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockDfirService.updateStatus).not.toHaveBeenCalled();
    });
  });

  describe('createLink', () => {
    const dto: CreateDfirLinkDto = {
      sourceType: DfirLinkSourceType.CTI_IOC,
      sourceId: 'ioc-1',
    };

    it('links a record via the service', async () => {
      const link = { id: 'link-1', incidentId: 'incident-1' };
      mockDfirService.linkRecord.mockResolvedValue(link);

      const result = await controller.createLink(analyst, 'incident-1', dto);

      expect(result).toEqual(link);
      expect(mockDfirService.linkRecord).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        DfirLinkSourceType.CTI_IOC,
        'ioc-1',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.createLink(noTenantAdmin, 'incident-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockDfirService.linkRecord).not.toHaveBeenCalled();
    });
  });
});
