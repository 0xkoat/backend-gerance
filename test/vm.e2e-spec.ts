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
import { VmService } from './../src/vm/vm.service';
import { PrismaService } from './../src/prisma/prisma.service';
import {
  ModuleName,
  Severity,
  UserRole,
  VmVulnerabilitiesStatus,
} from './../src/generated/prisma/enums';

describe('VmController (e2e)', () => {
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

  const mockVmService = {
    listAssets: jest.fn(),
    createAsset: jest.fn(),
    query: jest.fn(),
    updateVulnerabilityStatus: jest.fn(),
    assignVulnerability: jest.fn(),
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
      .overrideProvider(VmService)
      .useValue(mockVmService)
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

  describe('GET /vm/assets', () => {
    it('allows any authenticated tenant role to list assets', async () => {
      const token = await loginAs(viewerUser.email);
      mockVmService.listAssets.mockResolvedValue([
        { id: 'asset-1', tenantId: 'tenant-1' },
      ]);

      const response = await request(app.getHttpServer())
        .get('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockVmService.listAssets).toHaveBeenCalledWith('tenant-1');
      expect(response.body).toHaveLength(1);
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer()).get('/api/vm/assets').expect(401);
    });

    it('rejects a caller not scoped to a tenant', async () => {
      const token = await loginAs(noTenantAdminUser.email);

      await request(app.getHttpServer())
        .get('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockVmService.listAssets).not.toHaveBeenCalled();
    });
  });

  describe('POST /vm/assets', () => {
    const createBody = { name: 'web-server-1', ip: '10.0.0.5', type: 'server' };

    it('allows an Analyst to create an asset', async () => {
      const token = await loginAs(analystUser.email);
      mockVmService.createAsset.mockResolvedValue({
        id: 'asset-1',
        tenantId: 'tenant-1',
        ...createBody,
      });

      await request(app.getHttpServer())
        .post('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(201);

      expect(mockVmService.createAsset).toHaveBeenCalledWith(
        'tenant-1',
        createBody,
      );
    });

    it('allows an Admin to create an asset', async () => {
      const token = await loginAs(adminUser.email);
      mockVmService.createAsset.mockResolvedValue({
        id: 'asset-1',
        tenantId: 'tenant-1',
        ...createBody,
      });

      await request(app.getHttpServer())
        .post('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(201);
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .post('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(403);
      expect(mockVmService.createAsset).not.toHaveBeenCalled();
    });

    it('rejects a request with an invalid ip', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...createBody, ip: 'not-an-ip' })
        .expect(400);
      expect(mockVmService.createAsset).not.toHaveBeenCalled();
    });

    it('rejects a request missing required fields', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/vm/assets')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'web-server-1' })
        .expect(400);
    });
  });

  describe('GET /vm/vulnerabilities', () => {
    it('allows any authenticated tenant role and merges tenantId into the query', async () => {
      const token = await loginAs(viewerUser.email);
      mockVmService.query.mockResolvedValue([]);

      await request(app.getHttpServer())
        .get('/api/vm/vulnerabilities?severity=HIGH')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockVmService.query).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          severity: Severity.HIGH,
        }),
      );
    });

    it('rejects an invalid severity value', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .get('/api/vm/vulnerabilities?severity=NOT_A_SEVERITY')
        .set('Authorization', `Bearer ${token}`)
        .expect(400);
    });
  });

  describe('PATCH /vm/vulnerabilities/:id/status', () => {
    it('allows an Analyst to update the status', async () => {
      const token = await loginAs(analystUser.email);
      mockVmService.updateVulnerabilityStatus.mockResolvedValue({
        id: 'vuln-1',
        status: VmVulnerabilitiesStatus.REMEDIATED,
      });

      await request(app.getHttpServer())
        .patch('/api/vm/vulnerabilities/vuln-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: VmVulnerabilitiesStatus.REMEDIATED })
        .expect(200);

      expect(mockVmService.updateVulnerabilityStatus).toHaveBeenCalledWith(
        'tenant-1',
        'vuln-1',
        VmVulnerabilitiesStatus.REMEDIATED,
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .patch('/api/vm/vulnerabilities/vuln-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: VmVulnerabilitiesStatus.REMEDIATED })
        .expect(403);
      expect(mockVmService.updateVulnerabilityStatus).not.toHaveBeenCalled();
    });

    it('returns 404 when the service reports the vulnerability as not found', async () => {
      const token = await loginAs(adminUser.email);
      mockVmService.updateVulnerabilityStatus.mockRejectedValue(
        new NotFoundException('Vulnerability not found'),
      );

      await request(app.getHttpServer())
        .patch('/api/vm/vulnerabilities/missing-id/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: VmVulnerabilitiesStatus.REMEDIATED })
        .expect(404);
    });

    it('rejects an invalid status value', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .patch('/api/vm/vulnerabilities/vuln-1/status')
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'NOT_A_STATUS' })
        .expect(400);
      expect(mockVmService.updateVulnerabilityStatus).not.toHaveBeenCalled();
    });
  });

  describe('POST /vm/vulnerabilities/:id/assign', () => {
    it('allows an Analyst to self-assign', async () => {
      const token = await loginAs(analystUser.email);
      mockVmService.assignVulnerability.mockResolvedValue({
        id: 'vuln-1',
        assignedToUserId: 'analyst-1',
      });

      await request(app.getHttpServer())
        .post('/api/vm/vulnerabilities/vuln-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(201);

      expect(mockVmService.assignVulnerability).toHaveBeenCalledWith(
        'tenant-1',
        'vuln-1',
        expect.objectContaining({ role: UserRole.ANALYST }),
        undefined,
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .post('/api/vm/vulnerabilities/vuln-1/assign')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(403);
      expect(mockVmService.assignVulnerability).not.toHaveBeenCalled();
    });
  });

  describe('POST /vm/events', () => {
    const eventBody = {
      assetIP: '10.0.0.5',
      assetName: 'web-server-1',
      assetType: 'server',
      description: 'Outdated OpenSSL version',
      cveId: 'CVE-2026-1234',
      severity: Severity.HIGH,
    };

    it('allows an Admin to ingest an event', async () => {
      const token = await loginAs(adminUser.email);
      mockVmService.ingest.mockResolvedValue(undefined);

      await request(app.getHttpServer())
        .post('/api/vm/events')
        .set('Authorization', `Bearer ${token}`)
        .send(eventBody)
        .expect(201);

      expect(mockVmService.ingest).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          source: ModuleName.VM,
          type: 'vulnerability',
          severity: Severity.HIGH,
          data: expect.objectContaining({
            assetIP: '10.0.0.5',
            description: 'Outdated OpenSSL version',
          }),
        }),
      );
    });

    it('rejects an Analyst (ingestion is Admin-only)', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/api/vm/events')
        .set('Authorization', `Bearer ${token}`)
        .send(eventBody)
        .expect(403);
      expect(mockVmService.ingest).not.toHaveBeenCalled();
    });

    it('rejects a request with an invalid assetIP', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/api/vm/events')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...eventBody, assetIP: 'not-an-ip' })
        .expect(400);
      expect(mockVmService.ingest).not.toHaveBeenCalled();
    });

    it('rejects a request missing severity', async () => {
      const token = await loginAs(adminUser.email);
      const { severity: _severity, ...withoutSeverity } = eventBody;
      void _severity;

      await request(app.getHttpServer())
        .post('/api/vm/events')
        .set('Authorization', `Bearer ${token}`)
        .send(withoutSeverity)
        .expect(400);
      expect(mockVmService.ingest).not.toHaveBeenCalled();
    });
  });
});
