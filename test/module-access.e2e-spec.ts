import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { ModuleAccessService } from './../src/module-access/module-access.service';
import { AnalystLevel, UserRole } from './../src/generated/prisma/enums';

// Route-level RBAC and validation for /modules and /module-endpoints, through
// the real global guard chain. ModuleAccessService itself is mocked here; its
// launch/level rules are covered by module-access.service.spec.ts.
describe('Module access (e2e)', () => {
  let app: INestApplication<App>;

  const PASSWORD = 'Correct-password1!';
  let hashedPassword: string;

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
      analystLevel: AnalystLevel.L2,
      tenantId: 'tenant-1',
    },
  };

  const mockUsersService = { findByEmail: jest.fn() };
  const mockModuleAccessService = {
    listEndpoints: jest.fn().mockResolvedValue([]),
    updateEndpoint: jest.fn().mockResolvedValue({}),
    testConnection: jest.fn().mockResolvedValue({ reachable: true }),
    listForUser: jest.fn().mockResolvedValue([]),
    setMinLevel: jest.fn().mockResolvedValue({}),
    launch: jest.fn().mockResolvedValue({ url: 'https://10.0.0.5:5601/' }),
    recentLaunches: jest.fn().mockResolvedValue([]),
  };

  const validEndpoint = {
    protocol: 'HTTPS',
    host: '10.0.0.5',
    port: 5601,
    path: '/',
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
      .overrideProvider(ModuleAccessService)
      .useValue(mockModuleAccessService)
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

  describe('/module-endpoints', () => {
    it('lets an Integration Admin update an endpoint and records who did it', async () => {
      const token = await loginAs(users.integrationAdmin.email);

      await request(app.getHttpServer())
        .patch('/api/module-endpoints/SIEM')
        .set('Authorization', `Bearer ${token}`)
        .send(validEndpoint)
        .expect(200);

      expect(mockModuleAccessService.updateEndpoint).toHaveBeenCalledWith(
        'SIEM',
        validEndpoint,
        users.integrationAdmin.id,
      );
    });

    it.each([
      ['a URL instead of a host', { host: 'https://10.0.0.5' }],
      ['a port out of range', { port: 70000 }],
      ['a path without a leading slash', { path: 'login' }],
      ['an unknown protocol', { protocol: 'FTP' }],
    ])('rejects %s', async (_label, override) => {
      const token = await loginAs(users.integrationAdmin.email);

      await request(app.getHttpServer())
        .patch('/api/module-endpoints/SIEM')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...validEndpoint, ...override })
        .expect(400);
      expect(mockModuleAccessService.updateEndpoint).not.toHaveBeenCalled();
    });

    it('rejects an unknown module name', async () => {
      const token = await loginAs(users.integrationAdmin.email);

      await request(app.getHttpServer())
        .patch('/api/module-endpoints/NOPE')
        .set('Authorization', `Bearer ${token}`)
        .send(validEndpoint)
        .expect(400);
    });

    it('lets an Integration Admin run the connection test', async () => {
      const token = await loginAs(users.integrationAdmin.email);

      const response = await request(app.getHttpServer())
        .post('/api/module-endpoints/SIEM/test')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toEqual({ reachable: true });
    });

    it('lets a Super Admin read endpoints but not change them', async () => {
      const token = await loginAs(users.superAdmin.email);

      await request(app.getHttpServer())
        .get('/api/module-endpoints')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      await request(app.getHttpServer())
        .patch('/api/module-endpoints/SIEM')
        .set('Authorization', `Bearer ${token}`)
        .send(validEndpoint)
        .expect(403);
    });

    it.each([['admin'], ['analyst']] as const)(
      'rejects a tenant %s on every endpoint route',
      async (who) => {
        const token = await loginAs(users[who].email);

        await request(app.getHttpServer())
          .get('/api/module-endpoints')
          .set('Authorization', `Bearer ${token}`)
          .expect(403);
        await request(app.getHttpServer())
          .patch('/api/module-endpoints/SIEM')
          .set('Authorization', `Bearer ${token}`)
          .send(validEndpoint)
          .expect(403);
        await request(app.getHttpServer())
          .post('/api/module-endpoints/SIEM/test')
          .set('Authorization', `Bearer ${token}`)
          .expect(403);
      },
    );
  });

  describe('/modules', () => {
    it("lists an Analyst's modules using the token's tenant, role and level", async () => {
      const token = await loginAs(users.analyst.email);

      await request(app.getHttpServer())
        .get('/api/modules')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockModuleAccessService.listForUser).toHaveBeenCalledWith(
        'tenant-1',
        UserRole.ANALYST,
        AnalystLevel.L2,
      );
    });

    it('launches for an Analyst and returns the redirect URL', async () => {
      const token = await loginAs(users.analyst.email);

      const response = await request(app.getHttpServer())
        .post('/api/modules/SIEM/launch')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toEqual({ url: 'https://10.0.0.5:5601/' });
      expect(mockModuleAccessService.launch).toHaveBeenCalledWith(
        users.analyst.id,
        'tenant-1',
        'SIEM',
      );
    });

    it('lets a tenant Admin set a minimum level and read recent launches', async () => {
      const token = await loginAs(users.admin.email);

      await request(app.getHttpServer())
        .patch('/api/modules/SIEM/level')
        .set('Authorization', `Bearer ${token}`)
        .send({ minAnalystLevel: 'L1' })
        .expect(200);
      await request(app.getHttpServer())
        .get('/api/modules/launches')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockModuleAccessService.setMinLevel).toHaveBeenCalledWith(
        'tenant-1',
        'SIEM',
        'L1',
      );
    });

    it('rejects an invalid level', async () => {
      const token = await loginAs(users.admin.email);

      await request(app.getHttpServer())
        .patch('/api/modules/SIEM/level')
        .set('Authorization', `Bearer ${token}`)
        .send({ minAnalystLevel: 'L9' })
        .expect(400);
      expect(mockModuleAccessService.setMinLevel).not.toHaveBeenCalled();
    });

    it('does not let an Analyst change levels or read the launch log', async () => {
      const token = await loginAs(users.analyst.email);

      await request(app.getHttpServer())
        .patch('/api/modules/SIEM/level')
        .set('Authorization', `Bearer ${token}`)
        .send({ minAnalystLevel: 'L1' })
        .expect(403);
      await request(app.getHttpServer())
        .get('/api/modules/launches')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });

    it.each([['superAdmin'], ['integrationAdmin']] as const)(
      'does not let a platform-wide %s launch modules',
      async (who) => {
        const token = await loginAs(users[who].email);

        await request(app.getHttpServer())
          .post('/api/modules/SIEM/launch')
          .set('Authorization', `Bearer ${token}`)
          .expect(403);
        expect(mockModuleAccessService.launch).not.toHaveBeenCalled();
      },
    );
  });
});
