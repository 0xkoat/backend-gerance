import { Test, TestingModule } from '@nestjs/testing';
import {
  ConflictException,
  INestApplication,
  NotFoundException,
  ValidationPipe,
} from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { UserRole } from './../src/generated/prisma/enums';

describe('UsersController (e2e)', () => {
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
  }

  const adminUser: FakeUser = {
    id: 'admin-1',
    email: 'admin@x.com',
    name: 'Admin',
    phoneNumber: '+21612345678',
    role: UserRole.ADMIN,
    tenantId: 'tenant-1',
  };

  const analystUser: FakeUser = {
    id: 'analyst-1',
    email: 'analyst@x.com',
    name: 'Analyst',
    phoneNumber: '+21612345679',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
  };

  const viewerUser: FakeUser = {
    id: 'viewer-1',
    email: 'viewer@x.com',
    name: 'Viewer',
    phoneNumber: '+21612345680',
    role: UserRole.VIEWER,
    tenantId: 'tenant-1',
  };

  const noTenantAdminUser: FakeUser = {
    id: 'admin-no-tenant',
    email: 'admin-no-tenant@x.com',
    name: 'Admin No Tenant',
    phoneNumber: '+21612345681',
    role: UserRole.ADMIN,
    tenantId: null,
  };

  const usersByEmail: Record<string, FakeUser> = {
    [adminUser.email]: adminUser,
    [analystUser.email]: analystUser,
    [viewerUser.email]: viewerUser,
    [noTenantAdminUser.email]: noTenantAdminUser,
  };

  const mockUsersService = {
    findByEmail: jest.fn(),
    findByIdForTenant: jest.fn(),
    createUser: jest.fn(),
    findAllForTenant: jest.fn(),
    updateUserForTenant: jest.fn(),
    changeRoleForTenant: jest.fn(),
    removeUserForTenant: jest.fn(),
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
      .useValue({
        onModuleInit: jest.fn(),
        onModuleDestroy: jest.fn(),
      })
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

  describe('GET /users/me', () => {
    it('returns the caller own record for any authenticated role', async () => {
      const token = await loginAs(analystUser.email);
      mockUsersService.findByIdForTenant.mockResolvedValue({
        ...analystUser,
        hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).not.toHaveProperty('hashedPassword');
      expect(response.body).toMatchObject({ id: analystUser.id });
    });

    it('rejects a request with no token', () => {
      return request(app.getHttpServer()).get('/users/me').expect(401);
    });

    it('rejects a caller not scoped to a tenant', async () => {
      const token = await loginAs(noTenantAdminUser.email);

      await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });
  });

  describe('POST /users', () => {
    const createBody = {
      name: 'New Analyst',
      email: 'new-analyst@x.com',
      password: 'Str0ng!Passw0rd',
      phoneNumber: '+21620345699',
      role: UserRole.ANALYST,
    };

    it('allows an Admin to create a user in their own tenant', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.createUser.mockResolvedValue({
        ...createBody,
        id: 'new-1',
        tenantId: adminUser.tenantId,
        hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(201);

      expect(mockUsersService.createUser).toHaveBeenCalledWith(
        expect.objectContaining({ email: createBody.email }),
        UserRole.ANALYST,
        adminUser.tenantId,
      );
      expect(response.body).not.toHaveProperty('hashedPassword');
    });

    it('rejects an Analyst attempting to create a user', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(403);
      expect(mockUsersService.createUser).not.toHaveBeenCalled();
    });

    it('rejects a Viewer attempting to create a user', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${token}`)
        .send(createBody)
        .expect(403);
    });

    it('rejects a role outside the allowed set (e.g. SUPER_ADMIN)', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${token}`)
        .send({ ...createBody, role: UserRole.SUPER_ADMIN })
        .expect(400);
      expect(mockUsersService.createUser).not.toHaveBeenCalled();
    });

    it('rejects a request missing required fields', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${token}`)
        .send({ email: createBody.email })
        .expect(400);
    });
  });

  describe('GET /users', () => {
    it('allows an Admin to list users in their tenant', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.findAllForTenant.mockResolvedValue([
        { ...adminUser, hashedPassword },
        { ...analystUser, hashedPassword },
      ]);

      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(mockUsersService.findAllForTenant).toHaveBeenCalledWith(
        adminUser.tenantId,
      );
      expect(response.body).toHaveLength(2);
      (response.body as Array<Record<string, unknown>>).forEach((user) =>
        expect(user).not.toHaveProperty('hashedPassword'),
      );
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });
  });

  describe('GET /users/:id', () => {
    it('allows an Admin to fetch a user in their tenant', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.findByIdForTenant.mockResolvedValue({
        ...analystUser,
        hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .get(`/users/${analystUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).not.toHaveProperty('hashedPassword');
    });

    it('returns 404 when the service reports the user as not found', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.findByIdForTenant.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await request(app.getHttpServer())
        .get('/users/missing-id')
        .set('Authorization', `Bearer ${token}`)
        .expect(404);
    });

    it('rejects an Analyst', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .get(`/users/${adminUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });
  });

  describe('PATCH /users/:id', () => {
    it('allows an Admin to update a user in their tenant', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.updateUserForTenant.mockResolvedValue({
        ...analystUser,
        name: 'Updated Name',
        hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .patch(`/users/${analystUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Updated Name' })
        .expect(200);

      expect(response.body).toMatchObject({ name: 'Updated Name' });
      expect(response.body).not.toHaveProperty('hashedPassword');
    });

    it('rejects an attempt to change the role through this route', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .patch(`/users/${analystUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ role: UserRole.ADMIN })
        .expect(400);
      expect(mockUsersService.updateUserForTenant).not.toHaveBeenCalled();
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .patch(`/users/${analystUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Nope' })
        .expect(403);
    });
  });

  describe('PATCH /users/:id/role', () => {
    it('allows an Admin to change another user role', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.changeRoleForTenant.mockResolvedValue({
        ...analystUser,
        role: UserRole.VIEWER,
        hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .patch(`/users/${analystUser.id}/role`)
        .set('Authorization', `Bearer ${token}`)
        .send({ role: UserRole.VIEWER })
        .expect(200);

      expect(mockUsersService.changeRoleForTenant).toHaveBeenCalledWith(
        analystUser.id,
        adminUser.tenantId,
        UserRole.VIEWER,
      );
      expect(response.body).not.toHaveProperty('hashedPassword');
    });

    it('rejects an Admin changing their own role, without calling the service', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .patch(`/users/${adminUser.id}/role`)
        .set('Authorization', `Bearer ${token}`)
        .send({ role: UserRole.ANALYST })
        .expect(403);
      expect(mockUsersService.changeRoleForTenant).not.toHaveBeenCalled();
    });

    it('returns 409 when demoting the last remaining Admin', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.changeRoleForTenant.mockRejectedValue(
        new ConflictException(
          'Cannot demote the last remaining Admin in this tenant',
        ),
      );

      await request(app.getHttpServer())
        .patch(`/users/${analystUser.id}/role`)
        .set('Authorization', `Bearer ${token}`)
        .send({ role: UserRole.VIEWER })
        .expect(409);
    });

    it('rejects a role outside the allowed set', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .patch(`/users/${analystUser.id}/role`)
        .set('Authorization', `Bearer ${token}`)
        .send({ role: UserRole.SUPER_ADMIN })
        .expect(400);
      expect(mockUsersService.changeRoleForTenant).not.toHaveBeenCalled();
    });

    it('rejects an Analyst', async () => {
      const token = await loginAs(analystUser.email);

      await request(app.getHttpServer())
        .patch(`/users/${viewerUser.id}/role`)
        .set('Authorization', `Bearer ${token}`)
        .send({ role: UserRole.VIEWER })
        .expect(403);
    });
  });

  describe('DELETE /users/:id', () => {
    it('allows an Admin to delete another user and returns a confirmation', async () => {
      const token = await loginAs(adminUser.email);
      mockUsersService.removeUserForTenant.mockResolvedValue({
        ...analystUser,
        hashedPassword,
      });

      const response = await request(app.getHttpServer())
        .delete(`/users/${analystUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toEqual({
        message: 'User deleted successfully',
        id: analystUser.id,
      });
    });

    it('rejects an Admin deleting their own account, without calling the service', async () => {
      const token = await loginAs(adminUser.email);

      await request(app.getHttpServer())
        .delete(`/users/${adminUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
      expect(mockUsersService.removeUserForTenant).not.toHaveBeenCalled();
    });

    it('rejects a Viewer', async () => {
      const token = await loginAs(viewerUser.email);

      await request(app.getHttpServer())
        .delete(`/users/${analystUser.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(403);
    });
  });
});
