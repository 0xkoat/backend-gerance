import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { SiemController } from './siem.controller';
import { SiemService } from './siem.service';
import {
  ModuleName,
  Severity,
  SiemAlertStatus,
  UserRole,
} from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { IngestSiemEventDto } from './dto/ingestSiemEvent.dto';
import { UpdateSiemAlertStatusDto } from './dto/updateSiemAlertStatus.dto';
import { SiemQueryDto } from './dto/siemQuery.dto';
import { AssignDto } from '../common/dto/assign.dto';

const mockSiemService = {
  listLogs: jest.fn(),
  query: jest.fn(),
  assignAlert: jest.fn(),
  updateAlertStatus: jest.fn(),
  ingest: jest.fn(),
};

describe('SiemController', () => {
  let controller: SiemController;

  const analyst: AuthenticatedUser = {
    userId: 'user-1',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const admin: AuthenticatedUser = {
    userId: 'admin-1',
    role: UserRole.ADMIN,
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
      controllers: [SiemController],
      providers: [{ provide: SiemService, useValue: mockSiemService }],
    }).compile();

    controller = module.get<SiemController>(SiemController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('listLogs', () => {
    it('returns logs for the caller tenant', async () => {
      const logs = [{ id: 'log-1', tenantId: 'tenant-1' }];
      mockSiemService.listLogs.mockResolvedValue(logs);

      const result = await controller.listLogs(analyst);

      expect(result).toEqual(logs);
      expect(mockSiemService.listLogs).toHaveBeenCalledWith('tenant-1');
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.listLogs(noTenantAdmin)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockSiemService.listLogs).not.toHaveBeenCalled();
    });
  });

  describe('queryAlerts', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: SiemQueryDto = {
        severity: Severity.HIGH,
        page: 1,
        pageSize: 20,
      };
      mockSiemService.query.mockResolvedValue([]);

      await controller.queryAlerts(analyst, query);

      expect(mockSiemService.query).toHaveBeenCalledWith({
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.queryAlerts(noTenantAdmin, {})).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockSiemService.query).not.toHaveBeenCalled();
    });
  });

  describe('assignAlert', () => {
    const dto: AssignDto = {};

    it('passes the caller and requested assignee to the service', async () => {
      const updated = { id: 'alert-1', status: SiemAlertStatus.ASSIGNED };
      mockSiemService.assignAlert.mockResolvedValue(updated);

      const result = await controller.assignAlert(analyst, 'alert-1', {
        assignedToUserId: 'analyst-2',
      });

      expect(result).toEqual(updated);
      expect(mockSiemService.assignAlert).toHaveBeenCalledWith(
        'tenant-1',
        'alert-1',
        analyst,
        'analyst-2',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.assignAlert(noTenantAdmin, 'alert-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockSiemService.assignAlert).not.toHaveBeenCalled();
    });
  });

  describe('updateAlertStatus', () => {
    const dto: UpdateSiemAlertStatusDto = { status: SiemAlertStatus.RESOLVED };

    it('passes the caller and status to the service', async () => {
      const updated = { id: 'alert-1', status: SiemAlertStatus.RESOLVED };
      mockSiemService.updateAlertStatus.mockResolvedValue(updated);

      const result = await controller.updateAlertStatus(
        analyst,
        'alert-1',
        dto,
      );

      expect(result).toEqual(updated);
      expect(mockSiemService.updateAlertStatus).toHaveBeenCalledWith(
        'tenant-1',
        'alert-1',
        analyst,
        SiemAlertStatus.RESOLVED,
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateAlertStatus(noTenantAdmin, 'alert-1', dto),
      ).rejects.toThrow(ForbiddenException);
      expect(mockSiemService.updateAlertStatus).not.toHaveBeenCalled();
    });
  });

  describe('ingestEvent', () => {
    const dto: IngestSiemEventDto = {
      type: 'alert',
      severity: Severity.HIGH,
      title: 'Suspicious login',
    };

    it('builds a UnifiedEvent with source SIEM and the title nested under data', async () => {
      mockSiemService.ingest.mockResolvedValue(undefined);

      await controller.ingestEvent(admin, dto);

      expect(mockSiemService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.SIEM,
          type: 'alert',
          severity: Severity.HIGH,
          data: { title: 'Suspicious login' },
        }),
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.ingestEvent(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockSiemService.ingest).not.toHaveBeenCalled();
    });
  });
});
