import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { SiemService } from './../src/siem/siem.service';
import { PrismaService } from './../src/prisma/prisma.service';
import {
  ModuleName,
  Severity,
  SiemAlertStatus,
  UserRole,
} from './../src/generated/prisma/enums';

interface FakeUser {
  id: string;
  email: string;
  name: string;
  phoneNumber: string;
  role: UserRole;
  tenantId: string | null;
  mustChangePassword: boolean;
}

const PASSWORD = 'Correct-password1!';

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

describe('SiemController (e2e)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockSiemService = {
    listLogs: jest.fn(),
    query: jest.fn(),
    assignAlert: jest.fn(),
    unassignAlert: jest.fn(),
    updateAlertStatus: jest.fn(),
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
      .overrideProvider(SiemService)
      .useValue(mockSiemService)
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

  describe('GET /siem/logs', () => {
    it('allows any authenticated tenant role to list logs', async () => {
      const token = await loginAs(viewerUser.email);
      mockSiemService.listLogs.mockResolvedValue([
        { id: 'log-1', tenantId: 'tenant-1' },
      ]);

      const response = await request(app.getHttpServer())
        .get('/api/siem/logs')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockSiemService.listLogs).toHaveBeenCalledWith('tenant-1');
      expect(response.body).toHaveLength(1);
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer()).get('/api/siem/logs').expect(401);
    });
  });

  describe('GET /siem/alerts', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockSiemService.query.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/siem/alerts?severity=HIGH')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockSiemService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          severity: Severity.HIGH,
        }),
      );
    });
  });

  describe('POST /siem/alerts/:id/assign', () => {
    it('allows an Analyst to self-assign', async () => {
      const token = await loginAs(analystUser.email);
      mockSiemService.assignAlert.mockResolvedValue({
        id: 'alert-1',
        status: SiemAlertStatus.ASSIGNED,
      });

      await request(app.getHttpServer())
        .post('/api/siem/alerts/alert-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(201);

      expect(mockSiemService.assignAlert).toHaveBeenCalledWith(
        'tenant-1',
        'alert-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
        undefined,
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .post('/api/siem/alerts/alert-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(403);
      expect(mockSiemService.assignAlert).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /siem/alerts/:id/assign', () => {
    it('allows an Analyst to unassign', async () => {
      const token = await loginAs(analystUser.email);
      mockSiemService.unassignAlert.mockResolvedValue({
        id: 'alert-1',
        status: SiemAlertStatus.OPEN,
      });

      await request(app.getHttpServer())
        .delete('/api/siem/alerts/alert-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockSiemService.unassignAlert).toHaveBeenCalledWith(
        'tenant-1',
        'alert-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .delete('/api/siem/alerts/alert-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockSiemService.unassignAlert).not.toHaveBeenCalled();
    });
  });

  describe('PATCH /siem/alerts/:id/status', () => {
    it('allows an Analyst to update alert status', async () => {
      const token = await loginAs(analystUser.email);
      mockSiemService.updateAlertStatus.mockResolvedValue({
        id: 'alert-1',
        status: SiemAlertStatus.RESOLVED,
      });

      await request(app.getHttpServer())
        .patch('/api/siem/alerts/alert-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: SiemAlertStatus.RESOLVED })
        .expect(200);

      expect(mockSiemService.updateAlertStatus).toHaveBeenCalledWith(
        'tenant-1',
        'alert-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
        SiemAlertStatus.RESOLVED,
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .patch('/api/siem/alerts/alert-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: SiemAlertStatus.RESOLVED })
        .expect(403);
      expect(mockSiemService.updateAlertStatus).not.toHaveBeenCalled();
    });

    it('rejects a status value other than ESCALATED/RESOLVED', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .patch('/api/siem/alerts/alert-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: SiemAlertStatus.ASSIGNED })
        .expect(400);
      expect(mockSiemService.updateAlertStatus).not.toHaveBeenCalled();
    });
  });

  describe('POST /siem/events', () => {
    it('allows an Admin to ingest an event', async () => {
      const token = await loginAs(adminUser.email);
      mockSiemService.ingest.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .post('/api/siem/events')
        .set('Authorization', `Bearer ${token}`)
        .send({ type: 'alert', severity: Severity.HIGH, title: 'Manual alert' })
        .expect(201);

      expect(mockSiemService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.SIEM,
          type: 'alert',
          severity: Severity.HIGH,
          data: { title: 'Manual alert' },
        }),
      );
    });

    it('rejects an Analyst (ingestion is Admin-only)', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/siem/events')
        .set('Authorization', `Bearer ${token}`)
        .send({ type: 'alert', severity: Severity.HIGH })
        .expect(403);
      expect(mockSiemService.ingest).not.toHaveBeenCalled();
    });

    it('rejects an invalid type value', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/siem/events')
        .set('Authorization', `Bearer ${token}`)
        .send({ type: 'not-a-type', severity: Severity.HIGH })
        .expect(400);
      expect(mockSiemService.ingest).not.toHaveBeenCalled();
    });
  });
});

describe('EDR -> SIEM integration (e2e, real event chain)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  let siemAlerts: Array<Record<string, unknown>>;
  let idCounter: number;

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const statefulPrisma = {
    edrEndpoint: {
      upsert: jest
        .fn()
        .mockImplementation(({ create }: { create: Record<string, unknown> }) =>
          Promise.resolve({ id: 'endpoint-1', ...create }),
        ),
    },
    edrDetection: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) =>
          Promise.resolve({ id: `detection-${++idCounter}`, ...data }),
        ),
    },
    siemLog: {
      create: jest.fn().mockResolvedValue({ id: 'log-1' }),
    },
    siemAlert: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) => {
          const alert = {
            id: `alert-${++idCounter}`,
            createdAt: new Date(),
            ...data,
          };
          siemAlerts.push(alert);
          return Promise.resolve(alert);
        }),
      findMany: jest
        .fn()
        .mockImplementation(({ where }: { where: { tenantId: string } }) =>
          Promise.resolve(
            siemAlerts.filter((a) => a.tenantId === where.tenantId),
          ),
        ),
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    // Stubs below exist only so CTI's/SOAR's/Asset's real @OnEvent listeners
    // (also wired globally via AppModule) don't throw when this suite's
    // 'edr.detection.created'/'siem.alert.created' emits reach them — this
    // file doesn't assert on their behavior, it just needs them to no-op
    // cleanly.
    ctiIoc: {
      findFirst: jest.fn().mockResolvedValue(null),
    },
    soarPlaybook: {
      findMany: jest.fn().mockResolvedValue([]),
    },
    assetFeedEntry: {
      create: jest.fn().mockResolvedValue({}),
    },
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
    siemAlerts = [];
    idCounter = 0;
    mockUsersService.findByEmail.mockImplementation((email: string) => {
      const user = usersByEmail[email];
      return Promise.resolve(user ? { ...user, hashedPassword } : null);
    });

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(UsersService)
      .useValue(mockUsersService)
      .overrideProvider(PrismaService)
      .useValue({
        ...statefulPrisma,
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

  it('POSTing an EDR event produces a SIEM alert visible via GET /siem/alerts', async () => {
    const adminToken = await loginAs(adminUser.email);

    await request(app.getHttpServer())
      .post('/api/edr/events')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        hostname: 'web-server-1',
        ip: '10.0.0.5',
        os: 'Ubuntu 24.04',
        detectionName: 'Suspicious PowerShell execution chain',
        severity: Severity.HIGH,
      })
      .expect(201);

    const viewerToken = await loginAs(viewerUser.email);
    const response = await request(app.getHttpServer())
      .get('/api/siem/alerts')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const alerts = response.body as Array<{ title: string; tenantId: string }>;
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      tenantId: 'tenant-1',
      title: 'Suspicious PowerShell execution chain on web-server-1',
    });
  });
});
