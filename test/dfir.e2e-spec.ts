import { Test, TestingModule } from '@nestjs/testing';
import {
  INestApplication,
  NotFoundException,
  ValidationPipe,
} from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { DfirService } from './../src/dfir/dfir.service';
import { PrismaService } from './../src/prisma/prisma.service';
import {
  CtiIocType,
  DfirIncidentStatus,
  DfirLinkSourceType,
  Severity,
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

describe('DfirController (e2e)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockDfirService = {
    query: jest.fn(),
    getIncidentDetail: jest.fn(),
    assignIncident: jest.fn(),
    unassignIncident: jest.fn(),
    updateStatus: jest.fn(),
    linkRecord: jest.fn(),
    unlinkRecord: jest.fn(),
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
      .overrideProvider(DfirService)
      .useValue(mockDfirService)
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

  describe('GET /dfir/incidents', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockDfirService.query.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/dfir/incidents?status=OPEN')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockDfirService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          status: DfirIncidentStatus.OPEN,
        }),
      );
    });
  });

  describe('GET /dfir/incidents/:id', () => {
    it('returns the incident detail', async () => {
      const token = await loginAs(viewerUser.email);
      mockDfirService.getIncidentDetail.mockResolvedValue({
        id: 'incident-1',
        tenantId: 'tenant-1',
        links: [],
      });

      await request(app.getHttpServer())
        .get('/api/dfir/incidents/incident-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockDfirService.getIncidentDetail).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
      );
    });

    it('returns 404 when the service reports the incident as not found', async () => {
      const token = await loginAs(viewerUser.email);
      mockDfirService.getIncidentDetail.mockRejectedValue(
        new NotFoundException('Incident not found'),
      );

      await request(app.getHttpServer())
        .get('/api/dfir/incidents/missing-id')
        .set('Authorization', `Bearer ${token}`)
        .expect(404);
    });
  });

  describe('POST /dfir/incidents/:id/assign', () => {
    it('allows an Analyst to self-assign', async () => {
      const token = await loginAs(analystUser.email);
      mockDfirService.assignIncident.mockResolvedValue({
        id: 'incident-1',
        status: DfirIncidentStatus.INVESTIGATING,
      });

      await request(app.getHttpServer())
        .post('/api/dfir/incidents/incident-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(201);

      expect(mockDfirService.assignIncident).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
        undefined,
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .post('/api/dfir/incidents/incident-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(403);
      expect(mockDfirService.assignIncident).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /dfir/incidents/:id/assign', () => {
    it('allows an Analyst to unassign', async () => {
      const token = await loginAs(analystUser.email);
      mockDfirService.unassignIncident.mockResolvedValue({
        id: 'incident-1',
        status: DfirIncidentStatus.OPEN,
      });

      await request(app.getHttpServer())
        .delete('/api/dfir/incidents/incident-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockDfirService.unassignIncident).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .delete('/api/dfir/incidents/incident-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockDfirService.unassignIncident).not.toHaveBeenCalled();
    });
  });

  describe('PATCH /dfir/incidents/:id/status', () => {
    it('allows an Analyst to update incident status', async () => {
      const token = await loginAs(analystUser.email);
      mockDfirService.updateStatus.mockResolvedValue({
        id: 'incident-1',
        status: DfirIncidentStatus.RESOLVED,
      });

      await request(app.getHttpServer())
        .patch('/api/dfir/incidents/incident-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: DfirIncidentStatus.RESOLVED })
        .expect(200);

      expect(mockDfirService.updateStatus).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
        DfirIncidentStatus.RESOLVED,
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .patch('/api/dfir/incidents/incident-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: DfirIncidentStatus.RESOLVED })
        .expect(403);
      expect(mockDfirService.updateStatus).not.toHaveBeenCalled();
    });

    it('rejects a status value other than ESCALATED/CONTAINED/RESOLVED', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .patch('/api/dfir/incidents/incident-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: DfirIncidentStatus.INVESTIGATING })
        .expect(400);
      expect(mockDfirService.updateStatus).not.toHaveBeenCalled();
    });
  });

  describe('POST /dfir/incidents/:id/links', () => {
    it('allows an Analyst to link a record', async () => {
      const token = await loginAs(analystUser.email);
      mockDfirService.linkRecord.mockResolvedValue({ id: 'link-1' });

      await request(app.getHttpServer())
        .post('/api/dfir/incidents/incident-1/links')
        .set('Authorization', `Bearer ${token}`)
        .send({
          sourceType: DfirLinkSourceType.CTI_IOC,
          sourceId: '11111111-1111-4111-8111-111111111111',
        })
        .expect(201);

      expect(mockDfirService.linkRecord).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        DfirLinkSourceType.CTI_IOC,
        '11111111-1111-4111-8111-111111111111',
      );
    });

    it('rejects an invalid sourceId (not a UUID)', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/dfir/incidents/incident-1/links')
        .set('Authorization', `Bearer ${token}`)
        .send({
          sourceType: DfirLinkSourceType.CTI_IOC,
          sourceId: 'not-a-uuid',
        })
        .expect(400);
      expect(mockDfirService.linkRecord).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /dfir/incidents/:id/links/:linkId', () => {
    it('allows an Analyst to unlink a record', async () => {
      const token = await loginAs(analystUser.email);
      mockDfirService.unlinkRecord.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .delete('/api/dfir/incidents/incident-1/links/link-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockDfirService.unlinkRecord).toHaveBeenCalledWith(
        'tenant-1',
        'incident-1',
        'link-1',
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .delete('/api/dfir/incidents/incident-1/links/link-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockDfirService.unlinkRecord).not.toHaveBeenCalled();
    });
  });
});

describe('EDR -> SIEM -> CTI -> SOAR -> DFIR integration (e2e, full chain)', () => {
  let app: INestApplication<App>;
  let hashedPassword: string;

  let siemAlerts: Array<Record<string, unknown>>;
  let ctiIocs: Array<Record<string, unknown>>;
  let soarPlaybooks: Array<Record<string, unknown>>;
  let soarExecutions: Array<Record<string, unknown>>;
  let dfirIncidents: Array<Record<string, unknown>>;
  let dfirLinks: Array<Record<string, unknown>>;
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
    },
    // Same reasoning as the other stubs above, for Asset's real @OnEvent
    // listener on 'edr.detection.created'.
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
    soarPlaybooks = [];
    soarExecutions = [];
    dfirIncidents = [];
    dfirLinks = [];
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

  it('a single EDR event walks the entire chain and lands a DFIR incident linked to the alert and the execution', async () => {
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
      .get('/api/dfir/incidents')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const incidents = response.body as Array<{
      id: string;
      tenantId: string;
      title: string;
      severity: Severity;
    }>;
    expect(incidents).toHaveLength(1);
    expect(incidents[0]).toMatchObject({
      tenantId: 'tenant-1',
      severity: Severity.CRITICAL,
    });
    expect(incidents[0].title).toContain('Outbound C2 beaconing detected');

    const detailResponse = await request(app.getHttpServer())
      .get(`/api/dfir/incidents/${incidents[0].id}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    const detail = detailResponse.body as {
      links: Array<{ sourceType: string; sourceId: string }>;
    };
    expect(detail.links).toHaveLength(2);
    expect(detail.links.map((l) => l.sourceType).sort()).toEqual(
      [DfirLinkSourceType.SIEM_ALERT, DfirLinkSourceType.SOAR_EXECUTION].sort(),
    );
  });

  it('an EDR event with no matching IOC never reaches SOAR or DFIR', async () => {
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
      .get('/api/dfir/incidents')
      .set('Authorization', `Bearer ${viewerToken}`)
      .expect(200);

    expect(response.body).toEqual([]);
  });
});
