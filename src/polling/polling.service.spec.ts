import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { PollingService } from './polling.service';
import { MODULE_DATA_SOURCE_ADAPTER } from '../common/security-module/data-source-adapter.interface';
import { PrismaService } from '../prisma/prisma.service';
import { VmService } from '../vm/vm.service';
import { EdrService } from '../edr/edr.service';
import { SiemService } from '../siem/siem.service';
import { CtiService } from '../cti/cti.service';
import { SoarService } from '../soar/soar.service';
import { DfirService } from '../dfir/dfir.service';
import { ModuleName, Severity } from '../generated/prisma/enums';
import { RawRecord } from '../common/security-module/types';

const mockPrismaService = {
  tenantModule: {
    findMany: jest.fn(),
    update: jest.fn(),
  },
};

const mockAdapter = {
  fetchSince: jest.fn(),
};

const mockVmService = { ingest: jest.fn() };
const mockEdrService = { ingest: jest.fn() };
const mockSiemService = { ingest: jest.fn() };
const mockCtiService = { ingest: jest.fn() };
const mockSoarService = { ingest: jest.fn() };
const mockDfirService = { ingest: jest.fn() };

describe('PollingService', () => {
  let service: PollingService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PollingService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: MODULE_DATA_SOURCE_ADAPTER, useValue: mockAdapter },
        { provide: VmService, useValue: mockVmService },
        { provide: EdrService, useValue: mockEdrService },
        { provide: SiemService, useValue: mockSiemService },
        { provide: CtiService, useValue: mockCtiService },
        { provide: SoarService, useValue: mockSoarService },
        { provide: DfirService, useValue: mockDfirService },
      ],
    }).compile();

    service = module.get<PollingService>(PollingService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('pollOne', () => {
    const record: RawRecord = {
      timestamp: new Date('2026-08-05T15:00:00Z'),
      type: 'detection',
      severity: Severity.HIGH,
      data: { hostname: 'polled-host' },
    };

    it('fetches with no since when config has no lastSyncedAt, ingests through the matching module, and stamps lastSyncedAt', async () => {
      mockAdapter.fetchSince.mockResolvedValue([record]);
      mockEdrService.ingest.mockResolvedValue(undefined);
      mockPrismaService.tenantModule.update.mockResolvedValue({});

      const tenantModule = {
        id: 'tm-1',
        tenantId: 'tenant-1',
        moduleName: ModuleName.EDR,
        isActive: true,
        config: null,
      };

      await service.pollOne(tenantModule);

      expect(mockAdapter.fetchSince).toHaveBeenCalledWith(
        ModuleName.EDR,
        {},
        undefined,
      );
      expect(mockEdrService.ingest).toHaveBeenCalledWith({
        tenantId: 'tenant-1',
        timestamp: record.timestamp,
        source: ModuleName.EDR,
        type: 'detection',
        severity: Severity.HIGH,
        data: { hostname: 'polled-host' },
      });
      expect(mockPrismaService.tenantModule.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'tm-1' },
          data: {
            config: expect.objectContaining({
              lastSyncedAt: expect.any(String),
            }),
          },
        }),
      );
    });

    it('passes the parsed lastSyncedAt from config as since, preserving other config keys', async () => {
      mockAdapter.fetchSince.mockResolvedValue([]);
      mockPrismaService.tenantModule.update.mockResolvedValue({});

      const lastSyncedAt = '2026-08-01T00:00:00.000Z';
      const tenantModule = {
        id: 'tm-2',
        tenantId: 'tenant-1',
        moduleName: ModuleName.CTI,
        isActive: true,
        config: { apiKey: 'secret', lastSyncedAt },
      };

      await service.pollOne(tenantModule);

      expect(mockAdapter.fetchSince).toHaveBeenCalledWith(
        ModuleName.CTI,
        { apiKey: 'secret', lastSyncedAt },
        new Date(lastSyncedAt),
      );
      expect(mockPrismaService.tenantModule.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: {
            config: expect.objectContaining({
              apiKey: 'secret',
              lastSyncedAt: expect.any(String),
            }),
          },
        }),
      );
    });

    it('routes each module name to its own service', async () => {
      mockAdapter.fetchSince.mockResolvedValue([record]);
      const services: Array<[ModuleName, { ingest: jest.Mock }]> = [
        [ModuleName.VM, mockVmService],
        [ModuleName.EDR, mockEdrService],
        [ModuleName.SIEM, mockSiemService],
        [ModuleName.CTI, mockCtiService],
        [ModuleName.SOAR, mockSoarService],
        [ModuleName.DFIR, mockDfirService],
      ];

      for (const [moduleName, mockService] of services) {
        mockService.ingest.mockResolvedValue(undefined);
        mockPrismaService.tenantModule.update.mockResolvedValue({});

        await service.pollOne({
          id: `tm-${moduleName}`,
          tenantId: 'tenant-1',
          moduleName,
          isActive: true,
          config: null,
        });

        expect(mockService.ingest).toHaveBeenCalledWith(
          expect.objectContaining({ source: moduleName }),
        );
      }
    });

    it('ingests every record the adapter returns', async () => {
      const secondRecord: RawRecord = {
        timestamp: new Date('2026-08-05T15:05:00Z'),
        type: 'detection',
        severity: Severity.LOW,
        data: { hostname: 'polled-host-2' },
      };
      mockAdapter.fetchSince.mockResolvedValue([record, secondRecord]);
      mockPrismaService.tenantModule.update.mockResolvedValue({});

      await service.pollOne({
        id: 'tm-1',
        tenantId: 'tenant-1',
        moduleName: ModuleName.EDR,
        isActive: true,
        config: null,
      });

      expect(mockEdrService.ingest).toHaveBeenCalledTimes(2);
    });
  });

  describe('pollAll', () => {
    it('polls every active tenant module', async () => {
      mockPrismaService.tenantModule.findMany.mockResolvedValue([
        {
          id: 'tm-1',
          tenantId: 'tenant-1',
          moduleName: ModuleName.EDR,
          isActive: true,
          config: null,
        },
        {
          id: 'tm-2',
          tenantId: 'tenant-2',
          moduleName: ModuleName.VM,
          isActive: true,
          config: null,
        },
      ]);
      mockAdapter.fetchSince.mockResolvedValue([]);
      mockPrismaService.tenantModule.update.mockResolvedValue({});

      await service.pollAll();

      expect(mockPrismaService.tenantModule.findMany).toHaveBeenCalledWith({
        where: { isActive: true },
      });
      expect(mockAdapter.fetchSince).toHaveBeenCalledTimes(2);
      expect(mockPrismaService.tenantModule.update).toHaveBeenCalledTimes(2);
    });

    it('logs and continues to the next tenant when one poll throws', async () => {
      const errorSpy = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation();
      mockPrismaService.tenantModule.findMany.mockResolvedValue([
        {
          id: 'tm-1',
          tenantId: 'tenant-1',
          moduleName: ModuleName.EDR,
          isActive: true,
          config: null,
        },
        {
          id: 'tm-2',
          tenantId: 'tenant-2',
          moduleName: ModuleName.VM,
          isActive: true,
          config: null,
        },
      ]);
      mockAdapter.fetchSince
        .mockRejectedValueOnce(new Error('adapter unreachable'))
        .mockResolvedValueOnce([]);
      mockPrismaService.tenantModule.update.mockResolvedValue({});

      await service.pollAll();

      expect(mockAdapter.fetchSince).toHaveBeenCalledTimes(2);
      expect(errorSpy).toHaveBeenCalledWith(
        'Polling failed for tenant tenant-1 / EDR',
        expect.any(Error),
      );
      errorSpy.mockRestore();
    });
  });
});
