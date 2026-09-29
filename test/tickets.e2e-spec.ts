import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { TicketsService } from './../src/tickets/tickets.service';
import { NotificationsService } from './../src/tickets/notifications.service';
import { AnalystLevel, UserRole } from './../src/generated/prisma/enums';

// Route-level RBAC and validation for /tickets and /notifications through the
// real global guard chain; the ticket rules themselves are covered by
// tickets.service.spec.ts.
describe('Tickets and notifications (e2e)', () => {
  let app: INestApplication<App>;

  const PASSWORD = 'Correct-password1!';
  let hashedPassword: string;
  const TICKET_ID = '11111111-1111-4111-8111-111111111111';

  const users = {
    superAdmin: {
      id: 'sa-1',
      email: 'sa@x.com',
      role: UserRole.SUPER_ADMIN,
      analystLevel: null,
      tenantId: null,
    },
    integrationAdmin: {
      id: 'ia-1',
      email: 'ia@x.com',
      role: UserRole.INTEGRATION_ADMIN,
      analystLevel: null,
      tenantId: null,
    },
    admin: {
      id: 'admin-1',
      email: 'admin@x.com',
      role: UserRole.ADMIN,
      analystLevel: null,
      tenantId: 'tenant-1',
    },
    analyst: {
      id: 'analyst-1',
      email: 'analyst@x.com',
      role: UserRole.ANALYST,
      analystLevel: AnalystLevel.L1,
      tenantId: 'tenant-1',
    },
  };

  const mockUsersService = { findByEmail: jest.fn() };
  const mockTicketsService = {
    create: jest.fn().mockResolvedValue({ id: TICKET_ID }),
    list: jest.fn().mockResolvedValue([]),
    findOne: jest.fn().mockResolvedValue({ id: TICKET_ID }),
    updateStatus: jest.fn().mockResolvedValue({ id: TICKET_ID }),
  };
  const mockNotificationsService = {
    listForUser: jest
      .fn()
      .mockResolvedValue({ notifications: [], unreadCount: 0 }),
    markRead: jest.fn().mockResolvedValue({ unreadCount: 0 }),
    markAllRead: jest.fn().mockResolvedValue({ unreadCount: 0 }),
  };

  const validTicket = {
    title: 'SIEM unreachable',
    description: 'The SIEM login page times out since this morning.',
    category: 'MODULES',
    moduleName: 'SIEM',
  };

  async function loginAs(email: string): Promise<string> {
    const response = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email, password: PASSWORD })
      .expect(200);
    return (response.body as { access_token: string }).access_token;
  }

  beforeAll(async () => {
    hashedPassword = await argon2.hash(PASSWORD);
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    mockUsersService.findByEmail.mockImplementation((email: string) => {
      const user = Object.values(users).find((u) => u.email === email);
      return Promise.resolve(
        user
          ? {
              ...user,
              name: user.id,
              phoneNumber: '+21612345678',
              mustChangePassword: false,
              hashedPassword,
            }
          : null,
      );
    });

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(UsersService)
      .useValue(mockUsersService)
      .overrideProvider(TicketsService)
      .useValue(mockTicketsService)
      .overrideProvider(NotificationsService)
      .useValue(mockNotificationsService)
      .overrideProvider(PrismaService)
      .useValue({
        onModuleInit: jest.fn(),
        onModuleDestroy: jest.fn(),
        refreshToken: {
          create: jest.fn().mockResolvedValue({ id: 'refresh-token-stub' }),
        },
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
        forbidNonWhitelisted: true,
      }),
    );
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('/tickets', () => {
    it('lets an Analyst raise a ticket', async () => {
      const token = await loginAs(users.analyst.email);

      await request(app.getHttpServer())
        .post('/api/tickets')
        .set('Authorization', `Bearer ${token}`)
        .send(validTicket)
        .expect(201);

      expect(mockTicketsService.create).toHaveBeenCalledWith(
        expect.objectContaining({ userId: users.analyst.id }),
        validTicket,
      );
    });

    it.each([
      ['a too-short title', { title: 'x' }],
      ['a too-short description', { description: 'short' }],
      ['an unknown category', { category: 'BILLING' }],
      ['an unknown module', { moduleName: 'NOPE' }],
      ['a smuggled tenantId', { tenantId: 'tenant-2' }],
      ['a smuggled status', { status: 'RESOLVED' }],
    ])('rejects %s', async (_label, override) => {
      const token = await loginAs(users.analyst.email);

      await request(app.getHttpServer())
        .post('/api/tickets')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...validTicket, ...override })
        .expect(400);
      expect(mockTicketsService.create).not.toHaveBeenCalled();
    });

    it('rate limits ticket creation per user, not per address', async () => {
      const analystToken = await loginAs(users.analyst.email);
      const adminToken = await loginAs(users.admin.email);

      for (let i = 0; i < 10; i++) {
        await request(app.getHttpServer())
          .post('/api/tickets')
          .set('Authorization', `Bearer ${analystToken}`)
          .send(validTicket)
          .expect(201);
      }
      await request(app.getHttpServer())
        .post('/api/tickets')
        .set('Authorization', `Bearer ${analystToken}`)
        .send(validTicket)
        .expect(429);

      // Same test client address, different account: its own budget.
      await request(app.getHttpServer())
        .post('/api/tickets')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validTicket)
        .expect(201);
    });

    it.each([['integrationAdmin'], ['superAdmin']] as const)(
      'does not let a platform-wide %s raise a ticket',
      async (who) => {
        const token = await loginAs(users[who].email);

        await request(app.getHttpServer())
          .post('/api/tickets')
          .set('Authorization', `Bearer ${token}`)
          .send(validTicket)
          .expect(403);
      },
    );

    it('lets an Integration Admin list and handle tickets', async () => {
      const token = await loginAs(users.integrationAdmin.email);

      await request(app.getHttpServer())
        .get('/api/tickets?status=OPEN')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      await request(app.getHttpServer())
        .patch(`/api/tickets/${TICKET_ID}/status`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'IN_PROGRESS' })
        .expect(200);

      expect(mockTicketsService.list).toHaveBeenCalledWith(
        expect.objectContaining({ userId: users.integrationAdmin.id }),
        'OPEN',
      );
      expect(mockTicketsService.updateStatus).toHaveBeenCalledWith(
        expect.objectContaining({ userId: users.integrationAdmin.id }),
        TICKET_ID,
        'IN_PROGRESS',
      );
    });

    it('keeps the Super Admin out of tickets entirely', async () => {
      const token = await loginAs(users.superAdmin.email);

      await request(app.getHttpServer())
        .get('/api/tickets')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it('validates the status and the ticket id', async () => {
      const token = await loginAs(users.admin.email);

      await request(app.getHttpServer())
        .patch(`/api/tickets/${TICKET_ID}/status`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'CLOSED' })
        .expect(400);
      await request(app.getHttpServer())
        .get('/api/tickets/not-a-uuid')
        .set('Authorization', `Bearer ${token}`)
        .expect(400);
      expect(mockTicketsService.updateStatus).not.toHaveBeenCalled();
      expect(mockTicketsService.findOne).not.toHaveBeenCalled();
    });
  });

  describe('/notifications', () => {
    it("serves and clears only the caller's own notifications", async () => {
      const token = await loginAs(users.integrationAdmin.email);

      await request(app.getHttpServer())
        .get('/api/notifications')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      await request(app.getHttpServer())
        .patch(`/api/notifications/${TICKET_ID}/read`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      await request(app.getHttpServer())
        .post('/api/notifications/read-all')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockNotificationsService.listForUser).toHaveBeenCalledWith(
        users.integrationAdmin.id,
      );
      expect(mockNotificationsService.markRead).toHaveBeenCalledWith(
        users.integrationAdmin.id,
        TICKET_ID,
      );
      expect(mockNotificationsService.markAllRead).toHaveBeenCalledWith(
        users.integrationAdmin.id,
      );
    });

    it('requires authentication', async () => {
      await request(app.getHttpServer()).get('/api/notifications').expect(401);
    });
  });
});
