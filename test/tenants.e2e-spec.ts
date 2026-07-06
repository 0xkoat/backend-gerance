import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { UserRole } from './../src/generated/prisma/enums';

describe('TenantsController (e2e)', () => {
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

  const superAdminUser: FakeUser = {
    id: 'super-admin-1',
    email: 'super-admin@x.com',
    name: 'Super Admin',
    phoneNumber: '+21620000000',
    role: UserRole.SUPER_ADMIN,
    tenantId: null,
    mustChangePassword: false,
  };

  const adminUser: FakeUser = {
    id: 'admin-1',
    email: 'admin@x.com',
    name: 'Admin',
    phoneNumber: '+21620000001',
    role: UserRole.ADMIN,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const usersByEmail: Record<string, FakeUser> = {
    [superAdminUser.email]: superAdminUser,
    [adminUser.email]: adminUser,
  };

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  const mockPrismaService = {
    tenant: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      delete: jest.fn(),
    },
    user: {
      deleteMany: jest.fn(),
    },
    tenantModule: {
      deleteMany: jest.fn(),
    },
    $transaction: jest.fn(),
    onModuleInit: jest.fn(),
    onModuleDestroy: jest.fn(),
  };

  async function loginAs(email: string): Promise<string> {
    const response = await request(app.getHttpServer())
      .post('/auth/login')
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
      .overrideProvider(PrismaService)
      .useValue(mockPrismaService)
      .compile();

    app = moduleFixture.createNestApplication();
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

  describe('POST /tenants', () => {
    const createBody = {
      tenantName: 'Acme Corp',
      name: 'Alice Admin',
      email: 'alice@acme.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21620000099',
    };

    it('allows a Super Admin to create a tenant with its first Admin', async () => {
      const token = await loginAs(superAdminUser.email);
      mockPrismaService.$transaction.mockResolvedValue({
        tenant: {
          id: 'tenant-2',
          name: 'Acme Corp',
          createdAt: new Date().toISOString(),
        },
        admin: {
          id: 'new-admin-1',
          name: 'Alice Admin',
          email: 'alice@acme.com',
          phoneNumber: '+21620000099',
          role: UserRole.ADMIN,
          tenantId: 'tenant-2',
        },
      });

      const response = await request(app.getHttpServer())
        .post('/tenants')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(201);

      expect(mockPrismaService.$transaction).toHaveBeenCalled();
      expect(response.body).toMatchObject({
        tenant: { name: 'Acme Corp' },
        admin: { email: 'alice@acme.com' },
      });

      const body = response.body as { admin: Record<string, unknown> };
      expect(body.admin).not.toHaveProperty('hashedPassword');
    });

    it('rejects an Admin (not Super Admin)', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/tenants')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(403);
      expect(mockPrismaService.$transaction).not.toHaveBeenCalled();
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer())
        .post('/tenants')
        .send(createBody)
        .expect(401);
    });

    it('rejects a request missing required fields', async () => {
      const token = await loginAs(superAdminUser.email);

      await request(app.getHttpServer())
        .post('/tenants')
        .set('Authorization', `Bearer ${token}`)
        .send({ tenantName: 'Acme Corp' })
        .expect(400);
      expect(mockPrismaService.$transaction).not.toHaveBeenCalled();
    });
  });

  describe('GET /tenants', () => {
    it('allows a Super Admin to list all tenants', async () => {
      const token = await loginAs(superAdminUser.email);
      mockPrismaService.tenant.findMany.mockResolvedValue([
        {
          id: 'tenant-1',
          name: 'Tenant One',
          createdAt: new Date().toISOString(),
        },
        {
          id: 'tenant-2',
          name: 'Tenant Two',
          createdAt: new Date().toISOString(),
        },
      ]);

      const response = await request(app.getHttpServer())
        .get('/tenants')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toHaveLength(2);
    });

    it('rejects an Admin', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .get('/tenants')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });
  });

  describe('GET /tenants/:id', () => {
    it('allows a Super Admin to fetch a single tenant', async () => {
      const token = await loginAs(superAdminUser.email);
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
        name: 'Tenant One',
        createdAt: new Date().toISOString(),
      });

      const response = await request(app.getHttpServer())
        .get('/tenants/tenant-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: 'tenant-1',
        name: 'Tenant One',
      });
    });

    it('returns 404 when the tenant does not exist', async () => {
      const token = await loginAs(superAdminUser.email);
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await request(app.getHttpServer())
        .get('/tenants/missing-id')
        .set('Authorization', `Bearer ${token}`)
        .expect(404);
    });

    it('rejects an Admin', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .get('/tenants/tenant-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });
  });

  describe('DELETE /tenants/:id', () => {
    it('allows a Super Admin to delete a tenant and all its accounts', async () => {
      const token = await loginAs(superAdminUser.email);
      mockPrismaService.tenant.findUnique.mockResolvedValue({
        id: 'tenant-1',
        name: 'Tenant One',
        createdAt: new Date().toISOString(),
      });
      mockPrismaService.$transaction.mockResolvedValue([
        { count: 3 },
        { count: 1 },
        {
          id: 'tenant-1',
          name: 'Tenant One',
          createdAt: new Date().toISOString(),
        },
      ]);

      const response = await request(app.getHttpServer())
        .delete('/tenants/tenant-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockPrismaService.$transaction).toHaveBeenCalled();
      expect(response.body).toEqual({
        message: 'Tenant and all its accounts deleted successfully',
        id: 'tenant-1',
      });
    });

    it('returns 404 when the tenant does not exist', async () => {
      const token = await loginAs(superAdminUser.email);
      mockPrismaService.tenant.findUnique.mockResolvedValue(null);

      await request(app.getHttpServer())
        .delete('/tenants/missing-id')
        .set('Authorization', `Bearer ${token}`)
        .expect(404);
      expect(mockPrismaService.$transaction).not.toHaveBeenCalled();
    });

    it('rejects an Admin', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .delete('/tenants/tenant-1')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockPrismaService.$transaction).not.toHaveBeenCalled();
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer())
        .delete('/tenants/tenant-1')
        .expect(401);
    });
  });
});
