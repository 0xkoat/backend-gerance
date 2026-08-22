import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { CtiService } from './../src/cti/cti.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { Prisma } from './../src/generated/prisma/client';
import {
  CtiIocType,
  ModuleName,
  Severity,
  UserRole,
} from './../src/generated/prisma/enums';

function prismaConflictError() {
  return new Prisma.PrismaClientKnownRequestError('mocked P2002', {
    code: 'P2002',
    clientVersion: '7.8.0',
  });
}

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

describe('CtiController (e2e)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockCtiService = {
    query: jest.fn(),
    ingest: jest.fn(),
    updateIoc: jest.fn(),
    deleteIoc: jest.fn(),
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
      .overrideProvider(CtiService)
      .useValue(mockCtiService)
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

  describe('GET /cti/iocs', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockCtiService.query.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/cti/iocs?type=IP')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockCtiService.query).toHaveBeenCalledWith(
        expect.objectContaining({ tenantId: 'tenant-1', type: CtiIocType.IP }),
      );
    });
  });

  describe('POST /cti/iocs', () => {
    const body = {
      type: CtiIocType.IP,
      value: '185.220.101.47',
      confidence: 85,
      source: 'AlienVault OTX',
    };

    it('allows an Analyst to manually add an IOC', async () => {
      const token = await loginAs(analystUser.email);
      mockCtiService.ingest.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .post('/api/cti/iocs')
        .set('Authorization', `Bearer ${token}`)
        .send(body)
        .expect(201);

      expect(mockCtiService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.CTI,
          type: 'ioc',
          data: expect.objectContaining({ value: '185.220.101.47' }),
        }),
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .post('/api/cti/iocs')
        .set('Authorization', `Bearer ${token}`)
        .send(body)
        .expect(403);
      expect(mockCtiService.ingest).not.toHaveBeenCalled();
    });

    it('rejects a confidence value outside 0-100', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/cti/iocs')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...body, confidence: 150 })
        .expect(400);
      expect(mockCtiService.ingest).not.toHaveBeenCalled();
    });
  });

  describe('PATCH /cti/iocs/:id', () => {
    it('allows an Analyst to update confidence/source', async () => {
      const token = await loginAs(analystUser.email);
      mockCtiService.updateIoc.mockResolvedValue({
        id: 'ioc-1',
        tenantId: 'tenant-1',
        confidence: 40,
      });

      await request(app.getHttpServer())
        .patch('/api/cti/iocs/ioc-1')
        .set('Authorization', `Bearer ${token}`)
        .send({ confidence: 40 })
        .expect(200);

      expect(mockCtiService.updateIoc).toHaveBeenCalledWith(
        'tenant-1',
        'ioc-1',
        { confidence: 40 },
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .patch('/api/cti/iocs/ioc-1')
        .set('Authorization', `Bearer ${token}`)
        .send({ confidence: 40 })
        .expect(403);
      expect(mockCtiService.updateIoc).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /cti/iocs/:id', () => {
    it('allows an Analyst to delete an IOC', async () => {
      const token = await loginAs(analystUser.email);
      mockCtiService.deleteIoc.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .delete('/api/cti/iocs/ioc-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockCtiService.deleteIoc).toHaveBeenCalledWith(
        'tenant-1',
        'ioc-1',
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .delete('/api/cti/iocs/ioc-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockCtiService.deleteIoc).not.toHaveBeenCalled();
    });
  });

  describe('POST /cti/events', () => {
    it('rejects an Analyst (generic ingestion is Admin-only)', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/cti/events')
        .set('Authorization', `Bearer ${token}`)
        .send({
          type: CtiIocType.IP,
          value: '1.2.3.4',
          confidence: 50,
          source: 'test',
        })
        .expect(403);
      expect(mockCtiService.ingest).not.toHaveBeenCalled();
    });

    it('allows an Admin to ingest via the generic events route', async () => {
      const token = await loginAs(adminUser.email);
      mockCtiService.ingest.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .post('/api/cti/events')
        .set('Authorization', `Bearer ${token}`)
        .send({
          type: CtiIocType.IP,
          value: '1.2.3.4',
          confidence: 50,
          source: 'test',
        })
        .expect(201);

      expect(mockCtiService.ingest).toHaveBeenCalled();
    });
  });
});

describe('EDR -> SIEM -> CTI integration (e2e, real event chain)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  let siemAlerts: Array<Record<string, unknown>>;
  let ctiIocs: Array<Record<string, unknown>>;
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
      create: jest.fn().mockImplementation(
        ({
          data,
        }: {
          data: Record<string, unknown> & {
            tenantId: string;
            type: string;
            value: string;
          };
        }) => {
          const duplicate = ctiIocs.find(
            (i) =>
              i.tenantId === data.tenantId &&
              i.type === data.type &&
              i.value === data.value,
          );
          if (duplicate) {
            return Promise.reject(prismaConflictError());
          }
          const ioc = {
            id: `ioc-${++idCounter}`,
            createdAt: new Date(),
            ...data,
          };
          ctiIocs.push(ioc);
          return Promise.resolve(ioc);
        },
      ),
      update: jest.fn().mockImplementation(
        ({
          where,
          data,
        }: {
          where: {
            tenantId_type_value: {
              tenantId: string;
              type: string;
              value: string;
            };
          };
          data: Record<string, unknown>;
        }) => {
          const existing = ctiIocs.find(
            (i) =>
              i.tenantId === where.tenantId_type_value.tenantId &&
              i.type === where.tenantId_type_value.type &&
              i.value === where.tenantId_type_value.value,
          );
          if (existing) {
            Object.assign(existing, data);
          }
          return Promise.resolve(existing ?? null);
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
      findUnique: jest.fn().mockImplementation(
        ({
          where,
        }: {
          where: {
            tenantId_type_value: {
              tenantId: string;
              type: string;
              value: string;
            };
          };
        }) =>
          Promise.resolve(
            ctiIocs.find(
              (i) =>
                i.tenantId === where.tenantId_type_value.tenantId &&
                i.type === where.tenantId_type_value.type &&
                i.value === where.tenantId_type_value.value,
            ) ?? null,
          ),
      ),
    },
    // Stub below exists only so SOAR's real @OnEvent listeners (also wired
    // globally via AppModule) don't throw when this suite's
    // 'siem.alert.created'/'cti.enrichment.applied' emits reach them — this
    // file doesn't assert on SOAR's behavior, it just needs it to no-op.
    soarPlaybook: {
      findMany: jest.fn().mockResolvedValue([]),
    },
    // Same reasoning, for Asset's real @OnEvent listener on
    // 'edr.detection.created'.
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
    ctiIocs = [];
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

  it('an EDR event whose IP matches a known CTI IOC escalates the resulting SIEM alert to CRITICAL', async () => {
    const adminToken = await loginAs(adminUser.email);

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
      .get('/api/siem/alerts')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const alerts = response.body as Array<{
      severity: Severity;
      tenantId: string;
    }>;
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      tenantId: 'tenant-1',
      severity: Severity.CRITICAL,
    });
  });

  it('an EDR event with no matching IOC leaves the SIEM alert at its original severity', async () => {
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

    const alerts = response.body as Array<{ severity: Severity }>;
    expect(alerts).toHaveLength(1);
    expect(alerts[0].severity).toBe(Severity.HIGH);
  });
});
