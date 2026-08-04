import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { EdrService } from './../src/edr/edr.service';
import { PrismaService } from './../src/prisma/prisma.service';
import {
  ModuleName,
  Severity,
  UserRole,
} from './../src/generated/prisma/enums';

describe('EdrController (e2e)', () => {
  let app: INestApplication<App>;

  const PASSWORD = 'Correct-password1!';
  let hashedPassword: string;

  interface FakeUser {
    id: string;
    email: string;
    name: string;
    phoneNumber: string;
    role: UserRole;
    tenantId: string | null;
    mustChangePassword: boolean;
  }

  const adminUser: FakeUser = {
    id: 'admin-1',
    email: 'admin@x.com',
    name: 'Admin',
    phoneNumber: '+21612345678',
    role: UserRole.ADMIN,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const analystUser: FakeUser = {
    id: 'analyst-1',
    email: 'analyst@x.com',
    name: 'Analyst',
    phoneNumber: '+21612345679',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const viewerUser: FakeUser = {
    id: 'viewer-1',
    email: 'viewer@x.com',
    name: 'Viewer',
    phoneNumber: '+21612345680',
    role: UserRole.VIEWER,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const noTenantAdminUser: FakeUser = {
    id: 'admin-no-tenant',
    email: 'admin-no-tenant@x.com',
    name: 'Admin No Tenant',
    phoneNumber: '+21612345681',
    role: UserRole.ADMIN,
    tenantId: null,
    mustChangePassword: false,
  };

  const usersByEmail: Record<string, FakeUser> = {
    [adminUser.email]: adminUser,
    [analystUser.email]: analystUser,
    [viewerUser.email]: viewerUser,
    [noTenantAdminUser.email]: noTenantAdminUser,
  };

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockEdrService = {
    listEndpoints: jest.fn(),
    query: jest.fn(),
    ingest: jest.fn(),
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
      const user = usersByEmail[email];
      return Promise.resolve(user ? { ...user, hashedPassword } : null);
    });

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(UsersService)
      .useValue(mockUsersService)
      .overrideProvider(EdrService)
      .useValue(mockEdrService)
      .overrideProvider(PrismaService)
      .useValue({
        onModuleInit: jest.fn(),
        onModuleDestroy: jest.fn(),
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

  describe('GET /edr/endpoints', () => {
    it('allows any authenticated tenant role to list endpoints', async () => {
      const token = await loginAs(viewerUser.email);
      mockEdrService.listEndpoints.mockResolvedValue([
        { id: 'endpoint-1', tenantId: 'tenant-1' },
      ]);

      const response = await request(app.getHttpServer())
        .get('/api/edr/endpoints')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockEdrService.listEndpoints).toHaveBeenCalledWith('tenant-1');
      expect(response.body).toHaveLength(1);
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer()).get('/api/edr/endpoints').expect(401);
    });

    it('rejects a caller not scoped to a tenant', async () => {
      const token = await loginAs(noTenantAdminUser.email);

      await request(app.getHttpServer())
        .get('/api/edr/endpoints')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockEdrService.listEndpoints).not.toHaveBeenCalled();
    });
  });

  describe('GET /edr/detections', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockEdrService.query.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/edr/detections?severity=HIGH')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockEdrService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          severity: Severity.HIGH,
        }),
      );
    });

    it('rejects an invalid severity value', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .get('/api/edr/detections?severity=NOT_A_SEVERITY')
        .set('Authorization', `Bearer ${token}`)
        .expect(400);
    });
  });

  describe('POST /edr/events', () => {
    const eventBody = {
      hostname: 'web-server-1',
      ip: '10.0.0.5',
      os: 'Ubuntu 24.04',
      detectionName: 'Suspicious PowerShell execution chain',
      severity: Severity.HIGH,
    };

    it('allows an Admin to ingest an event', async () => {
      const token = await loginAs(adminUser.email);
      mockEdrService.ingest.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .post('/api/edr/events')
        .set('Authorization', `Bearer ${token}`)
        .send(eventBody)
        .expect(201);

      expect(mockEdrService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.EDR,
          type: 'detection',
          severity: Severity.HIGH,
          data: expect.objectContaining({
            hostname: 'web-server-1',
            detectionName: 'Suspicious PowerShell execution chain',
          }),
        }),
      );
    });

    it('rejects an Analyst (ingestion is Admin-only)', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/edr/events')
        .set('Authorization', `Bearer ${token}`)
        .send(eventBody)
        .expect(403);
      expect(mockEdrService.ingest).not.toHaveBeenCalled();
    });

    it('rejects a request with an invalid ip', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/edr/events')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...eventBody, ip: 'not-an-ip' })
        .expect(400);
      expect(mockEdrService.ingest).not.toHaveBeenCalled();
    });

    it('rejects a request missing required fields', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/edr/events')
        .set('Authorization', `Bearer ${token}`)
        .send({ hostname: 'web-server-1' })
        .expect(400);
      expect(mockEdrService.ingest).not.toHaveBeenCalled();
    });
  });
});
