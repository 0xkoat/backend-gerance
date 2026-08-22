import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { CtiController } from './cti.controller';
import { CtiService } from './cti.service';
import { CtiIocType, ModuleName, UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { CreateCtiIocDto } from './dto/createCtiIoc.dto';
import { CtiQueryDto } from './dto/ctiQuery.dto';

const mockCtiService = {
  query: jest.fn(),
  ingest: jest.fn(),
  updateIoc: jest.fn(),
  deleteIoc: jest.fn(),
};

describe('CtiController', () => {
  let controller: CtiController;

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
      controllers: [CtiController],
      providers: [{ provide: CtiService, useValue: mockCtiService }],
    }).compile();

    controller = module.get<CtiController>(CtiController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('queryIocs', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: CtiQueryDto = { type: CtiIocType.IP, page: 1, pageSize: 20 };
      mockCtiService.query.mockResolvedValue([]);

      await controller.queryIocs(analyst, query);

      expect(mockCtiService.query).toHaveBeenCalledWith({
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.queryIocs(noTenantAdmin, {})).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockCtiService.query).not.toHaveBeenCalled();
    });
  });

  describe('createIoc', () => {
    const dto: CreateCtiIocDto = {
      type: CtiIocType.IP,
      value: '185.220.101.47',
      confidence: 85,
      source: 'AlienVault OTX',
    };

    it('allows an Analyst to manually add an IOC', async () => {
      mockCtiService.ingest.mockResolvedValue(undefined);

      await controller.createIoc(analyst, dto);

      expect(mockCtiService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.CTI,
          type: 'ioc',
          data: {
            type: CtiIocType.IP,
            value: '185.220.101.47',
            confidence: 85,
            source: 'AlienVault OTX',
          },
        }),
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.createIoc(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockCtiService.ingest).not.toHaveBeenCalled();
    });
  });

  describe('updateIoc', () => {
    it('passes the tenant and id to the service', async () => {
      const updated = { id: 'ioc-1', tenantId: 'tenant-1', confidence: 40 };
      mockCtiService.updateIoc.mockResolvedValue(updated);

      const result = await controller.updateIoc(analyst, 'ioc-1', {
        confidence: 40,
      });

      expect(result).toEqual(updated);
      expect(mockCtiService.updateIoc).toHaveBeenCalledWith(
        'tenant-1',
        'ioc-1',
        { confidence: 40 },
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.updateIoc(noTenantAdmin, 'ioc-1', { confidence: 40 }),
      ).rejects.toThrow(ForbiddenException);
      expect(mockCtiService.updateIoc).not.toHaveBeenCalled();
    });
  });

  describe('deleteIoc', () => {
    it('passes the tenant and id to the service', async () => {
      mockCtiService.deleteIoc.mockResolvedValue(undefined);

      await controller.deleteIoc(analyst, 'ioc-1');

      expect(mockCtiService.deleteIoc).toHaveBeenCalledWith(
        'tenant-1',
        'ioc-1',
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.deleteIoc(noTenantAdmin, 'ioc-1'),
      ).rejects.toThrow(ForbiddenException);
      expect(mockCtiService.deleteIoc).not.toHaveBeenCalled();
    });
  });

  describe('ingestEvent', () => {
    const dto: CreateCtiIocDto = {
      type: CtiIocType.DOMAIN,
      value: 'malicious.example.com',
      confidence: 90,
      source: 'internal-feed',
    };

    it('allows an Admin to ingest an IOC via the generic events route', async () => {
      mockCtiService.ingest.mockResolvedValue(undefined);

      await controller.ingestEvent(admin, dto);

      expect(mockCtiService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.CTI,
          type: 'ioc',
          data: expect.objectContaining({ value: 'malicious.example.com' }),
        }),
      );
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(controller.ingestEvent(noTenantAdmin, dto)).rejects.toThrow(
        ForbiddenException,
      );
      expect(mockCtiService.ingest).not.toHaveBeenCalled();
    });
  });
});
