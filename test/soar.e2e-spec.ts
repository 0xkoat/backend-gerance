import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { SoarService } from './../src/soar/soar.service';
import { PrismaService } from './../src/prisma/prisma.service';
import {
  CtiIocType,
  Severity,
  SoarExecutionStatus,
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

describe('SoarController (e2e)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockSoarService = {
    listPlaybooks: jest.fn(),
    createPlaybook: jest.fn(),
    query: jest.fn(),
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
      .overrideProvider(SoarService)
      .useValue(mockSoarService)
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

  describe('GET /soar/playbooks', () => {
    it('allows any authenticated tenant role to list playbooks', async () => {
      const token = await loginAs(viewerUser.email);
      mockSoarService.listPlaybooks.mockResolvedValue([
        { id: 'playbook-1', tenantId: 'tenant-1' },
      ]);

      const response = await request(app.getHttpServer())
        .get('/api/soar/playbooks')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockSoarService.listPlaybooks).toHaveBeenCalledWith('tenant-1');
      expect(response.body).toHaveLength(1);
    });
  });

  describe('POST /soar/playbooks', () => {
    const body = {
      name: 'Isolate host on critical alert',
      triggerCondition: { severity: 'CRITICAL' },
      actions: { isolateHost: true },
    };

    it('allows an Admin to create a playbook', async () => {
      const token = await loginAs(adminUser.email);
      mockSoarService.createPlaybook.mockResolvedValue({
        id: 'playbook-1',
        tenantId: 'tenant-1',
        ...body,
      });

      await request(app.getHttpServer())
        .post('/api/soar/playbooks')
        .set('Authorization', `Bearer ${token}`)
        .send(body)
        .expect(201);

      expect(mockSoarService.createPlaybook).toHaveBeenCalledWith(
        'tenant-1',
        body,
      );
    });

    it('rejects an Analyst (playbook management is Admin-only)', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/soar/playbooks')
        .set('Authorization', `Bearer ${token}`)
        .send(body)
        .expect(403);
      expect(mockSoarService.createPlaybook).not.toHaveBeenCalled();
    });

    it('rejects a request missing required fields', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/soar/playbooks')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Incomplete' })
        .expect(400);
      expect(mockSoarService.createPlaybook).not.toHaveBeenCalled();
    });
  });

  describe('GET /soar/executions', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockSoarService.query.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/soar/executions?status=SUCCESS')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockSoarService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          status: SoarExecutionStatus.SUCCESS,
        }),
      );
    });

    it('rejects a caller not scoped to a tenant', async () => {
      const token = await loginAs(noTenantAdminUser.email);

      await request(app.getHttpServer())
        .get('/api/soar/executions')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockSoarService.query).not.toHaveBeenCalled();
    });
  });
});

describe('EDR -> SIEM -> CTI -> SOAR integration (e2e, real event chain)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  let siemAlerts: Array<Record<string, unknown>>;
  let ctiIocs: Array<Record<string, unknown>>;
  let soarPlaybooks: Array<Record<string, unknown>>;
  let soarExecutions: Array<Record<string, unknown>>;
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
      findUnique: jest
        .fn()
        .mockImplementation(({ where }: { where: { id: string } }) =>
          Promise.resolve(siemAlerts.find((a) => a.id === where.id) ?? null),
        ),
      findMany: jest
        .fn()
        .mockImplementation(({ where }: { where: { tenantId: string } }) =>
          Promise.resolve(
            siemAlerts.filter((a) => a.tenantId === where.tenantId),
          ),
        ),
      updateMany: jest
        .fn()
        .mockImplementation(
          ({
            where,
            data,
          }: {
            where: { id: string; tenantId: string };
            data: Record<string, unknown>;
          }) => {
            let count = 0;
            siemAlerts = siemAlerts.map((a) => {
              if (a.id === where.id && a.tenantId === where.tenantId) {
                count += 1;
                return { ...a, ...data };
              }
              return a;
            });
            return Promise.resolve({ count });
          },
        ),
    },
    ctiIoc: {
      upsert: jest
        .fn()
        .mockImplementation(
          ({ create }: { create: Record<string, unknown> }) => {
            const ioc = {
              id: `ioc-${++idCounter}`,
              createdAt: new Date(),
              ...create,
            };
            ctiIocs.push(ioc);
            return Promise.resolve(ioc);
          },
        ),
      findFirst: jest
        .fn()
        .mockImplementation(
          ({ where }: { where: { tenantId: string; value: string } }) =>
            Promise.resolve(
              ctiIocs.find(
                (i) => i.tenantId === where.tenantId && i.value === where.value,
              ) ?? null,
            ),
        ),
    },
    soarPlaybook: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) => {
          const playbook = {
            id: `playbook-${++idCounter}`,
            createdAt: new Date(),
            ...data,
          };
          soarPlaybooks.push(playbook);
          return Promise.resolve(playbook);
        }),
      findMany: jest
        .fn()
        .mockImplementation(({ where }: { where: { tenantId: string } }) =>
          Promise.resolve(
            soarPlaybooks.filter((p) => p.tenantId === where.tenantId),
          ),
        ),
    },
    soarExecution: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) => {
          const execution = {
            id: `execution-${++idCounter}`,
            createdAt: new Date(),
            ...data,
          };
          soarExecutions.push(execution);
          return Promise.resolve(execution);
        }),
      findMany: jest
        .fn()
        .mockImplementation(({ where }: { where: { tenantId: string } }) =>
          Promise.resolve(
            soarExecutions.filter((e) => e.tenantId === where.tenantId),
          ),
        ),
    },
    // Stubs below exist only so DFIR's real @OnEvent listener (also wired
    // globally via AppModule) doesn't throw when this suite's
    // 'soar.execution.created' emits reach it — this file doesn't assert on
    // DFIR's behavior, it just needs it to complete cleanly.
    dfirIncident: {
      create: jest
        .fn()
        .mockResolvedValue({ id: 'incident-stub', tenantId: 'tenant-1' }),
      findUnique: jest
        .fn()
        .mockResolvedValue({ id: 'incident-stub', tenantId: 'tenant-1' }),
    },
    dfirLink: {
      create: jest.fn().mockResolvedValue({ id: 'link-stub' }),
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
    ctiIocs = [];
    soarPlaybooks = [];
    soarExecutions = [];
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

  it('a CTI-escalated alert fires a matching playbook and creates a SOAR execution', async () => {
    const adminToken = await loginAs(adminUser.email);

    await request(app.getHttpServer())
      .post('/api/soar/playbooks')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Isolate host on critical alert',
        triggerCondition: { severity: 'CRITICAL' },
        actions: { isolateHost: true },
      })
      .expect(201);

    await request(app.getHttpServer())
      .post('/api/cti/iocs')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        type: CtiIocType.IP,
        value: '185.220.101.47',
        confidence: 90,
        source: 'AlienVault OTX',
      })
      .expect(201);

    await request(app.getHttpServer())
      .post('/api/edr/events')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        hostname: 'web-server-1',
        ip: '185.220.101.47',
        os: 'Ubuntu 24.04',
        detectionName: 'Outbound C2 beaconing detected',
        severity: Severity.HIGH,
      })
      .expect(201);

    const viewerToken = await loginAs(viewerUser.email);
    const response = await request(app.getHttpServer())
      .get('/api/soar/executions')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const executions = response.body as Array<{
      tenantId: string;
      status: SoarExecutionStatus;
    }>;
    expect(executions).toHaveLength(1);
    expect(executions[0]).toMatchObject({
      tenantId: 'tenant-1',
      status: SoarExecutionStatus.SUCCESS,
    });
  });

  it('an alert that never reaches CRITICAL does not fire the playbook', async () => {
    const adminToken = await loginAs(adminUser.email);

    await request(app.getHttpServer())
      .post('/api/soar/playbooks')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Isolate host on critical alert',
        triggerCondition: { severity: 'CRITICAL' },
        actions: { isolateHost: true },
      })
      .expect(201);

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
      .get('/api/soar/executions')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    expect(response.body).toEqual([]);
  });
});
