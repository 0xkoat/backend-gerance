import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { AssetService } from './../src/asset/asset.service';
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

const viewerUser: FakeUser = {
  id: 'viewer-1',
  email: 'viewer@x.com',
  name: 'Viewer',
  phoneNumber: '+21612345680',
  role: UserRole.VIEWER,
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
  [viewerUser.email]: viewerUser,
  [noTenantAdminUser.email]: noTenantAdminUser,
  [analystUser.email]: analystUser,
};

describe('AssetController (e2e)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockAssetService = {
    getUnifiedFeed: jest.fn(),
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
      .overrideProvider(AssetService)
      .useValue(mockAssetService)
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

  describe('GET /assets/feed', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockAssetService.getUnifiedFeed.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/assets/feed?severity=HIGH')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockAssetService.getUnifiedFeed).toHaveBeenCalledWith(
        'tenant-1',
        expect.objectContaining({
          tenantId: 'tenant-1',
          severity: Severity.HIGH,
        }),
      );
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer()).get('/api/assets/feed').expect(401);
    });

    it('rejects a caller with no tenant', async () => {
      const token = await loginAs(noTenantAdminUser.email);

      await request(app.getHttpServer())
        .get('/api/assets/feed')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockAssetService.getUnifiedFeed).not.toHaveBeenCalled();
    });
  });
});

describe('EDR -> SIEM -> CTI -> SOAR -> DFIR -> Asset feed integration (e2e, full chain)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  let siemAlerts: Array<Record<string, unknown>>;
  let ctiIocs: Array<Record<string, unknown>>;
  let soarPlaybooks: Array<Record<string, unknown>>;
  let soarExecutions: Array<Record<string, unknown>>;
  let dfirIncidents: Array<Record<string, unknown>>;
  let dfirLinks: Array<Record<string, unknown>>;
  let assetFeedEntries: Array<Record<string, unknown>>;
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
      update: jest
        .fn()
        .mockImplementation(
          ({
            where,
            data,
          }: {
            where: { id: string };
            data: Record<string, unknown>;
          }) => {
            let updated: Record<string, unknown> | undefined;
            siemAlerts = siemAlerts.map((a) => {
              if (a.id === where.id) {
                updated = { ...a, ...data };
                return updated;
              }
              return a;
            });
            return Promise.resolve(updated);
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
      // Backs DfirService.linkRecord's per-sourceType tenant-ownership check
      // for SOAR_EXECUTION links, same reasoning as siemAlert.findUnique above.
      findUnique: jest
        .fn()
        .mockImplementation(({ where }: { where: { id: string } }) =>
          Promise.resolve(
            soarExecutions.find((e) => e.id === where.id) ?? null,
          ),
        ),
    },
    dfirIncident: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) => {
          const incident = {
            id: `incident-${++idCounter}`,
            createdAt: new Date(),
            ...data,
          };
          dfirIncidents.push(incident);
          return Promise.resolve(incident);
        }),
      findUnique: jest
        .fn()
        .mockImplementation(
          ({
            where,
            include,
          }: {
            where: { id: string };
            include?: { links: boolean };
          }) => {
            const incident = dfirIncidents.find((i) => i.id === where.id);
            if (!incident) {
              return Promise.resolve(null);
            }
            if (include?.links) {
              return Promise.resolve({
                ...incident,
                links: dfirLinks.filter((l) => l.incidentId === incident.id),
              });
            }
            return Promise.resolve(incident);
          },
        ),
      findMany: jest
        .fn()
        .mockImplementation(({ where }: { where: { tenantId: string } }) =>
          Promise.resolve(
            dfirIncidents.filter((i) => i.tenantId === where.tenantId),
          ),
        ),
    },
    dfirLink: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) => {
          const link = { id: `link-${++idCounter}`, ...data };
          dfirLinks.push(link);
          return Promise.resolve(link);
        }),
      findFirst: jest.fn().mockImplementation(
        ({
          where,
        }: {
          where: {
            incidentId: string;
            sourceType: string;
            sourceId: string;
          };
        }) =>
          Promise.resolve(
            dfirLinks.find(
              (l) =>
                l.incidentId === where.incidentId &&
                l.sourceType === where.sourceType &&
                l.sourceId === where.sourceId,
            ) ?? null,
          ),
      ),
    },
    assetFeedEntry: {
      create: jest
        .fn()
        .mockImplementation(({ data }: { data: Record<string, unknown> }) => {
          const entry = {
            id: `feed-${++idCounter}`,
            createdAt: new Date(),
            ...data,
          };
          assetFeedEntries.push(entry);
          return Promise.resolve(entry);
        }),
      findMany: jest.fn().mockImplementation(
        ({
          where,
          skip = 0,
          take = 20,
        }: {
          where: {
            tenantId: string;
            severity?: Severity;
            timestamp?: { gte?: Date; lte?: Date };
          };
          skip?: number;
          take?: number;
        }) => {
          let results = assetFeedEntries.filter(
            (e) => e.tenantId === where.tenantId,
          );
          if (where.severity) {
            results = results.filter((e) => e.severity === where.severity);
          }
          if (where.timestamp?.gte) {
            results = results.filter(
              (e) => (e.timestamp as Date) >= where.timestamp!.gte!,
            );
          }
          if (where.timestamp?.lte) {
            results = results.filter(
              (e) => (e.timestamp as Date) <= where.timestamp!.lte!,
            );
          }
          results = [...results].sort(
            (a, b) =>
              (b.timestamp as Date).getTime() - (a.timestamp as Date).getTime(),
          );
          return Promise.resolve(results.slice(skip, skip + take));
        },
      ),
      updateMany: jest
        .fn()
        .mockImplementation(
          ({
            where,
            data,
          }: {
            where: { tenantId: string; source: ModuleName; sourceId: string };
            data: Record<string, unknown>;
          }) => {
            let count = 0;
            assetFeedEntries = assetFeedEntries.map((e) => {
              if (
                e.tenantId === where.tenantId &&
                e.source === where.source &&
                e.sourceId === where.sourceId
              ) {
                count += 1;
                return { ...e, ...data };
              }
              return e;
            });
            return Promise.resolve({ count });
          },
        ),
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
    dfirIncidents = [];
    dfirLinks = [];
    assetFeedEntries = [];
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

  it('a single EDR event walks the entire chain and every hop lands its own entry in the asset feed', async () => {
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
      .get('/api/assets/feed')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const feed = response.body as Array<{
      id: string;
      tenantId: string;
      source: ModuleName;
      type: string;
      severity: Severity;
      timestamp: string;
      summary: string;
      sourceId: string;
    }>;

    // The CTI IOC manually added via POST /api/cti/iocs is itself a
    // cti.ioc.created feed entry, plus one entry per chain hop
    // (EDR detection, SIEM alert, SOAR execution, DFIR incident) = 5 total.
    expect(feed).toHaveLength(5);
    expect(feed.every((entry) => entry.tenantId === 'tenant-1')).toBe(true);
    expect(feed.map((entry) => entry.source).sort()).toEqual(
      [
        ModuleName.CTI,
        ModuleName.DFIR,
        ModuleName.EDR,
        ModuleName.SIEM,
        ModuleName.SOAR,
      ].sort(),
    );

    // orderBy: timestamp desc is honored — non-increasing throughout. (Not
    // asserting a specific hop is first: the chain runs fast enough in this
    // test that some hops tie at millisecond resolution, and a stable sort
    // then keeps insertion order for ties rather than reordering them.)
    const timestamps = feed.map((entry) => new Date(entry.timestamp).getTime());
    expect(timestamps).toEqual([...timestamps].sort((a, b) => b - a));

    // The CTI IOC was added first, well before the EDR event kicked off the
    // rest of the chain, so it should unambiguously sort last regardless of
    // any millisecond ties among the chain's own hops.
    expect(feed[feed.length - 1].source).toBe(ModuleName.CTI);
  });

  it('an EDR event with no matching IOC still lands an EDR/SIEM feed entry but never a SOAR/DFIR one', async () => {
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
      .get('/api/assets/feed')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const feed = response.body as Array<{ source: ModuleName }>;
    expect(feed.map((entry) => entry.source).sort()).toEqual(
      [ModuleName.EDR, ModuleName.SIEM].sort(),
    );
  });

  it('assigning and resolving a SIEM alert updates its feed entry in place, not just the alert itself', async () => {
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

    const alertId = siemAlerts[0].id as string;

    const feedBeforeAssign = (
      await request(app.getHttpServer())
        .get('/api/assets/feed')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200)
    ).body as Array<{
      source: ModuleName;
      sourceId: string;
      status: string | null;
      assignedToUserId: string | null;
    }>;
    const siemEntryBefore = feedBeforeAssign.find(
      (e) => e.source === ModuleName.SIEM && e.sourceId === alertId,
    );
    expect(siemEntryBefore?.status).toBe('OPEN');
    expect(siemEntryBefore?.assignedToUserId).toBeNull();

    const analystToken = await loginAs(analystUser.email);
    await request(app.getHttpServer())
      .post(`/api/siem/alerts/${alertId}/assign`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({})
      .expect(201);

    const feedAfterAssign = (
      await request(app.getHttpServer())
        .get('/api/assets/feed')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200)
    ).body as Array<{
      source: ModuleName;
      sourceId: string;
      status: string | null;
      assignedToUserId: string | null;
    }>;
    const siemEntryAfterAssign = feedAfterAssign.find(
      (e) => e.source === ModuleName.SIEM && e.sourceId === alertId,
    );
    expect(siemEntryAfterAssign?.status).toBe('ASSIGNED');
    expect(siemEntryAfterAssign?.assignedToUserId).toBe(analystUser.id);

    await request(app.getHttpServer())
      .patch(`/api/siem/alerts/${alertId}/status`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ status: 'RESOLVED' })
      .expect(200);

    const feedAfterResolve = (
      await request(app.getHttpServer())
        .get('/api/assets/feed')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200)
    ).body as Array<{
      source: ModuleName;
      sourceId: string;
      status: string | null;
      assignedToUserId: string | null;
    }>;
    const siemEntryAfterResolve = feedAfterResolve.find(
      (e) => e.source === ModuleName.SIEM && e.sourceId === alertId,
    );
    expect(siemEntryAfterResolve?.status).toBe('RESOLVED');
    // The assignee is untouched by the status-only transition.
    expect(siemEntryAfterResolve?.assignedToUserId).toBe(analystUser.id);
  });
});
