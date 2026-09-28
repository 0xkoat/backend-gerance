import { Test, TestingModule } from '@nestjs/testing';
import { of } from 'rxjs';
import { EventsController } from './events.controller';
import { EventsService } from './events.service';
import { UserRole } from '../generated/prisma/enums';
import type { AuthenticatedUser } from '../auth/jwt.strategy';

const mockEventsService = {
  streamForUser: jest.fn(),
};

describe('EventsController', () => {
  let controller: EventsController;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [EventsController],
      providers: [{ provide: EventsService, useValue: mockEventsService }],
    }).compile();

    controller = module.get<EventsController>(EventsController);
  });

  it('streams for the caller, including a tenant-less Integration Admin', () => {
    const integrationAdmin: AuthenticatedUser = {
      userId: 'ia-1',
      role: UserRole.INTEGRATION_ADMIN,
      analystLevel: null,
      tenantId: null,
      mustChangePassword: false,
    };
    const stream$ = of({ data: {} });
    mockEventsService.streamForUser.mockReturnValue(stream$);

    expect(controller.stream(integrationAdmin)).toBe(stream$);
    expect(mockEventsService.streamForUser).toHaveBeenCalledWith('ia-1');
  });
});
