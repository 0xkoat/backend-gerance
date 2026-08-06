import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { AssetController } from './asset.controller';
import { AssetService } from './asset.service';
import { Severity, UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';
import { BaseQueryDto } from '../common/dto/base-query.dto';

const mockAssetService = {
  getUnifiedFeed: jest.fn(),
};

describe('AssetController', () => {
  let controller: AssetController;

  const viewer: AuthenticatedUser = {
    userId: 'user-1',
    role: UserRole.VIEWER,
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
      controllers: [AssetController],
      providers: [{ provide: AssetService, useValue: mockAssetService }],
    }).compile();

    controller = module.get<AssetController>(AssetController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getUnifiedFeed', () => {
    it('merges the query params with the caller tenantId', async () => {
      const query: BaseQueryDto = {
        severity: Severity.HIGH,
        page: 1,
        pageSize: 20,
      };
      mockAssetService.getUnifiedFeed.mockResolvedValue([]);

      await controller.getUnifiedFeed(viewer, query);

      expect(mockAssetService.getUnifiedFeed).toHaveBeenCalledWith('tenant-1', {
        ...query,
        tenantId: 'tenant-1',
      });
    });

    it('returns whatever the service resolves to', async () => {
      const rows = [{ id: 'entry-1', tenantId: 'tenant-1' }];
      mockAssetService.getUnifiedFeed.mockResolvedValue(rows);

      const result = await controller.getUnifiedFeed(viewer, {});

      expect(result).toEqual(rows);
    });

    it('throws ForbiddenException when the caller has no tenant', async () => {
      await expect(
        controller.getUnifiedFeed(noTenantAdmin, {}),
      ).rejects.toThrow(ForbiddenException);
      expect(mockAssetService.getUnifiedFeed).not.toHaveBeenCalled();
    });
  });
});
