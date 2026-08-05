import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { App } from 'supertest/types';
import * as argon2 from 'argon2';
import { AppModule } from './../src/app.module';
import { UsersService } from './../src/users/users.service';
import { PrismaService } from './../src/prisma/prisma.service';
import { UserRole } from './../src/generated/prisma/enums';

interface FakeUser {
  id: string;
  email: string;
  name: string;
  phoneNumber: string;
  role: UserRole;
  tenantId: string | null;
  mustChangePassword: boolean;
}

interface FakeRefreshToken {
  id: string;
  userId: string;
  tokenHash: string;
  familyId: string;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedByTokenId: string | null;
}

describe('Auth refresh/logout flow (e2e)', () => {
  let app: INestApplication<App>;

  const PASSWORD = 'Correct-password1!';
  let hashedPassword: string;

  const analystUser: FakeUser = {
    id: 'analyst-1',
    email: 'analyst@x.com',
    name: 'Analyst',
    phoneNumber: '+21612345679',
    role: UserRole.ANALYST,
    tenantId: 'tenant-1',
    mustChangePassword: false,
  };

  const usersByEmail: Record<string, FakeUser> = {
    [analystUser.email]: analystUser,
  };
  const usersById: Record<string, FakeUser> = {
    [analystUser.id]: analystUser,
  };

  const mockUsersService = {
    findByEmail: jest.fn(),
  };

  let refreshTokens: FakeRefreshToken[];
  let idCounter: number;

  function findMatching(
    row: FakeRefreshToken,
    where: { familyId?: string; tokenHash?: string; revokedAt?: null },
  ): boolean {
    if (where.familyId !== undefined && row.familyId !== where.familyId) {
      return false;
    }
    if (where.tokenHash !== undefined && row.tokenHash !== where.tokenHash) {
      return false;
    }
    if (where.revokedAt === null && row.revokedAt !== null) {
      return false;
    }
    return true;
  }

  const mockPrismaService = {
    onModuleInit: jest.fn(),
    onModuleDestroy: jest.fn(),
    user: {
      findUnique: jest
        .fn()
        .mockImplementation(({ where: { id } }: { where: { id: string } }) =>
          Promise.resolve(
            usersById[id] ? { ...usersById[id], hashedPassword } : null,
          ),
        ),
    },
    refreshToken: {
      create: jest
        .fn()
        .mockImplementation(
          ({
            data,
          }: {
            data: Omit<
              FakeRefreshToken,
              'id' | 'revokedAt' | 'replacedByTokenId'
            >;
          }) => {
            const row: FakeRefreshToken = {
              id: `rt-${++idCounter}`,
              ...data,
              revokedAt: null,
              replacedByTokenId: null,
            };
            refreshTokens.push(row);
            return Promise.resolve(row);
          },
        ),
      findUnique: jest
        .fn()
        .mockImplementation(
          ({ where: { tokenHash } }: { where: { tokenHash: string } }) =>
            Promise.resolve(
              refreshTokens.find((t) => t.tokenHash === tokenHash) ?? null,
            ),
        ),
      update: jest
        .fn()
        .mockImplementation(
          ({
            where: { id },
            data,
          }: {
            where: { id: string };
            data: Partial<FakeRefreshToken>;
          }) => {
            const row = refreshTokens.find((t) => t.id === id);
            if (row) {
              Object.assign(row, data);
            }
            return Promise.resolve(row ?? null);
          },
        ),
      updateMany: jest
        .fn()
        .mockImplementation(
          ({
            where,
            data,
          }: {
            where: { familyId?: string; tokenHash?: string; revokedAt?: null };
            data: Partial<FakeRefreshToken>;
          }) => {
            let count = 0;
            refreshTokens.forEach((row) => {
              if (findMatching(row, where)) {
                Object.assign(row, data);
                count++;
              }
            });
            return Promise.resolve({ count });
          },
        ),
    },
  };

  function extractCookie(res: request.Response): string {
    const setCookie = res.headers['set-cookie'] as unknown as string[];
    return setCookie[0].split(';')[0];
  }

  beforeAll(async () => {
    hashedPassword = await argon2.hash(PASSWORD);
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    refreshTokens = [];
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
      .useValue(mockPrismaService)
      .overrideGuard(ThrottlerGuard)
      .useValue({ canActivate: () => true })
      .compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());
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

  it('logs in, sets an httpOnly refresh cookie, and never exposes the raw refresh token in the body', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: analystUser.email, password: PASSWORD })
      .expect(200);

    expect(res.body).toEqual({
      access_token: expect.any(String),
      mustChangePassword: false,
    });
    const setCookie = res.headers['set-cookie'] as unknown as string[];
    expect(setCookie[0]).toContain('refresh_token=');
    expect(setCookie[0]).toContain('HttpOnly');
    expect(setCookie[0]).toContain('Path=/api/auth');
  });

  it('rejects /auth/refresh when no cookie is presented', async () => {
    await request(app.getHttpServer()).post('/api/auth/refresh').expect(401);
  });

  it('rotates the refresh token on use and rejects reuse of the old one, revoking the whole chain', async () => {
    const loginRes = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: analystUser.email, password: PASSWORD })
      .expect(200);
    const firstCookie = extractCookie(loginRes);

    const refreshRes = await request(app.getHttpServer())
      .post('/api/auth/refresh')
      .set('Cookie', firstCookie)
      .expect(200);
    const secondCookie = extractCookie(refreshRes);
    expect((refreshRes.body as { access_token: string }).access_token).toEqual(
      expect.any(String),
    );

    // The refresh token itself must rotate — a fresh JWT isn't guaranteed to
    // differ byte-for-byte from the previous one when issued within the same
    // second (identical payload + identical `iat` sign identically).
    expect(secondCookie).not.toEqual(firstCookie);

    // Replaying the already-rotated (now revoked) first token is treated as
    // theft: it's rejected, AND it kills the entire family — so the
    // legitimately-rotated second token stops working too.
    await request(app.getHttpServer())
      .post('/api/auth/refresh')
      .set('Cookie', firstCookie)
      .expect(401);

    await request(app.getHttpServer())
      .post('/api/auth/refresh')
      .set('Cookie', secondCookie)
      .expect(401);
  });

  it('logs out, clears the cookie, and the revoked token can no longer refresh', async () => {
    const loginRes = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: analystUser.email, password: PASSWORD })
      .expect(200);
    const cookie = extractCookie(loginRes);
    const accessToken = (loginRes.body as { access_token: string })
      .access_token;

    const logoutRes = await request(app.getHttpServer())
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', cookie)
      .expect(200);

    expect(logoutRes.body).toEqual({ message: 'Logged out' });
    const clearedCookie = (
      logoutRes.headers['set-cookie'] as unknown as string[]
    )[0];
    expect(clearedCookie).toContain('refresh_token=;');

    await request(app.getHttpServer())
      .post('/api/auth/refresh')
      .set('Cookie', cookie)
      .expect(401);
  });

  it('rejects /auth/logout without a valid access token', async () => {
    await request(app.getHttpServer()).post('/api/auth/logout').expect(401);
  });
});
