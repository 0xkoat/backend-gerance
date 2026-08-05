import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import helmet from 'helmet';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { UserRole } from './../src/generated/prisma/enums';

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;

  const dbUser = {
    id: '1',
    email: 'bob@x.com',
    name: 'Bob',
    phoneNumber: '+21612345678',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    hashedPassword: '',
    mustChangePassword: false,
    failedLoginAttempts: 0,
    lockedUntil: null,
  };

  const mockUsersService = {
    findByEmail: jest.fn(),
    requestPasswordReset: jest.fn(),
  };

  beforeAll(async () => {
    dbUser.hashedPassword = await argon2.hash('Correct-password1!');
  });

  beforeEach(async () => {
    mockUsersService.findByEmail.mockReset();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(UsersService)
      .useValue(mockUsersService)
      .overrideProvider(PrismaService)
      .useValue({
        onModuleInit: jest.fn(),
        onModuleDestroy: jest.fn(),
        refreshToken: {
          create: jest.fn().mockResolvedValue({ id: 'refresh-token-stub' }),
        },
        user: { update: jest.fn().mockResolvedValue({}) },
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.use(helmet());
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

  it('rejects a protected route with no token', () => {
    return request(app.getHttpServer()).get('/api/').expect(401);
  });

  it('logs in with valid credentials and returns an access_token', async () => {
    mockUsersService.findByEmail.mockResolvedValue(dbUser);

    const response = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'bob@x.com', password: 'Correct-password1!' })
      .expect(200);

    const body = response.body as { access_token: string };
    expect(body.access_token).toEqual(expect.any(String));
  });

  it('rejects login with the wrong password', () => {
    mockUsersService.findByEmail.mockResolvedValue(dbUser);

    return request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'bob@x.com', password: 'wrong-password' })
      .expect(401);
  });

  it('accepts a real JWT on a protected route with no @Roles() restriction', async () => {
    mockUsersService.findByEmail.mockResolvedValue(dbUser);

    const loginResponse = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'bob@x.com', password: 'Correct-password1!' })
      .expect(200);

    const { access_token: token } = loginResponse.body as {
      access_token: string;
    };

    return request(app.getHttpServer())
      .get('/api/')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect('Hello World!');
  });

  it('login response includes mustChangePassword', async () => {
    mockUsersService.findByEmail.mockResolvedValue(dbUser);

    const response = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'bob@x.com', password: 'Correct-password1!' })
      .expect(200);

    expect(response.body).toMatchObject({ mustChangePassword: false });
  });

  describe('POST /auth/forgot-password', () => {
    it('returns a generic message when the email exists', async () => {
      mockUsersService.requestPasswordReset.mockResolvedValue(undefined);

      const response = await request(app.getHttpServer())
        .post('/api/auth/forgot-password')
        .send({ email: 'bob@x.com' })
        .expect(200);

      expect(mockUsersService.requestPasswordReset).toHaveBeenCalledWith(
        'bob@x.com',
      );
      expect(response.body).toEqual({
        message:
          'If an account exists with this email, your administrator has been notified.',
      });
    });

    it('returns the same generic message when the email does not exist (no enumeration)', async () => {
      mockUsersService.requestPasswordReset.mockResolvedValue(undefined);

      const response = await request(app.getHttpServer())
        .post('/api/auth/forgot-password')
        .send({ email: 'missing@x.com' })
        .expect(200);

      expect(response.body).toEqual({
        message:
          'If an account exists with this email, your administrator has been notified.',
      });
    });

    it('requires no authentication', () => {
      mockUsersService.requestPasswordReset.mockResolvedValue(undefined);

      return request(app.getHttpServer())
        .post('/api/auth/forgot-password')
        .send({ email: 'bob@x.com' })
        .expect(200);
    });

    it('rejects an invalid email format', () => {
      return request(app.getHttpServer())
        .post('/api/auth/forgot-password')
        .send({ email: 'not-an-email' })
        .expect(400);
    });
  });

  describe('security headers', () => {
    it('applies helmet headers to responses', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/forgot-password')
        .send({ email: 'bob@x.com' })
        .expect(200);

      expect(response.headers['x-frame-options']).toBe('SAMEORIGIN');
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-dns-prefetch-control']).toBe('off');
    });
  });

  describe('rate limiting on auth routes', () => {
    it('returns 429 after exceeding the per-minute attempt limit on /auth/login', async () => {
      mockUsersService.findByEmail.mockResolvedValue(dbUser);

      for (let i = 0; i < 5; i++) {
        await request(app.getHttpServer())
          .post('/api/auth/login')
          .send({ email: 'bob@x.com', password: 'wrong-password' })
          .expect(401);
      }

      await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: 'bob@x.com', password: 'wrong-password' })
        .expect(429);
    });
  });
});
