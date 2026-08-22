import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { of } from 'rxjs';
import { EventsController } from './events.controller';
import { EventsService } from './events.service';
import { UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

const mockEventsService = {
  streamForTenant: jest.fn(),
};

describe('EventsController', () => {
  let controller: EventsController;

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
      controllers: [EventsController],
      providers: [{ provide: EventsService, useValue: mockEventsService }],
    }).compile();

    controller = module.get<EventsController>(EventsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('stream', () => {
    it('streams for the caller tenant', () => {
      const stream$ = of({ data: { tenantId: 'tenant-1' } });
      mockEventsService.streamForTenant.mockReturnValue(stream$);

      const result = controller.stream(viewer);

      expect(mockEventsService.streamForTenant).toHaveBeenCalledWith(
        'tenant-1',
      );
      expect(result).toBe(stream$);
    });

    it('throws ForbiddenException when the caller has no tenant', () => {
      expect(() => controller.stream(noTenantAdmin)).toThrow(
        ForbiddenException,
      );
      expect(mockEventsService.streamForTenant).not.toHaveBeenCalled();
    });
  });
});
