import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { User } from '../generated/prisma/client';
import * as argon2 from 'argon2';
import { randomBytes, randomUUID, createHash } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';

type SafeUser = Omit<User, 'hashedPassword'>;

const DUMMY_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$GI8yFc6QCemSdwM0skhZvg$3elgnlxE0oIy891fIvSi8cabR0CpJgR2fGQ/xqKpOys';

const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

export interface TokenPair {
  accessToken: string;
  mustChangePassword: boolean;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  // Locked-account rejections deliberately look identical to a wrong
  // password (same message, same argon2.verify call run unconditionally
  // beforehand) — this codebase already treats "does this email exist" as
  // secret, and a distinct "account locked" response would both leak that
  // and reopen the timing side-channel the dummy-hash verify exists to close.
  async validateUser(email: string, password: string): Promise<SafeUser> {
    const user = await this.usersService.findByEmail(email);

    const isPasswordValid = await argon2.verify(
      user?.hashedPassword ?? DUMMY_HASH,
      password,
    );

    const isLocked = !!user?.lockedUntil && user.lockedUntil > new Date();

    if (!user || !isPasswordValid || isLocked) {
      // Only a genuine wrong-password attempt against a currently-unlocked
      // account counts — attempts made while already locked don't extend
      // the lockout further, bounding it to a fixed 15-minute window no
      // matter how many times it's hammered during that window.
      if (user && !isLocked) {
        await this.registerFailedLogin(user);
      }
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.failedLoginAttempts > 0 || user.lockedUntil) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: 0, lockedUntil: null },
      });
    }

    const { hashedPassword, ...userWithoutPassword } = user;

    return userWithoutPassword;
  }

  async login(user: SafeUser): Promise<TokenPair> {
    const refresh = await this.issueRefreshToken(user.id, randomUUID());

    return {
      accessToken: this.signAccessToken(user),
      mustChangePassword: user.mustChangePassword,
      refreshToken: refresh.raw,
      refreshTokenExpiresAt: refresh.expiresAt,
    };
  }

  // Rotates on every use: the presented token is revoked and a new one is
  // issued in the same family. If a token that's already been revoked shows
  // up again, that's a replay of a stolen token — the whole family is killed
  // rather than just rejecting the one request, forcing a fresh login.
  async refresh(rawRefreshToken: string): Promise<TokenPair> {
    const tokenHash = this.hashToken(rawRefreshToken);
    const existing = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
    });

    if (!existing) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (existing.revokedAt) {
      await this.prisma.refreshToken.updateMany({
        where: { familyId: existing.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (existing.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const dbUser = await this.prisma.user.findUnique({
      where: { id: existing.userId },
    });
    if (!dbUser) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    const { hashedPassword, ...user } = dbUser;

    const newRefresh = await this.issueRefreshToken(
      existing.userId,
      existing.familyId,
    );

    // Conditional on revokedAt still being null (not a plain update) so two
    // concurrent requests presenting the same not-yet-revoked token can't
    // both win: only the first to land this write actually revokes it. If
    // the count comes back 0, another request already revoked it between our
    // read above and this write — that's the exact same "reuse" shape the
    // revokedAt branch above exists to catch, so treat it identically and
    // kill the whole family (including the token we just minted).
    const { count } = await this.prisma.refreshToken.updateMany({
      where: { id: existing.id, revokedAt: null },
      data: { revokedAt: new Date(), replacedByTokenId: newRefresh.id },
    });

    if (count === 0) {
      await this.prisma.refreshToken.updateMany({
        where: { familyId: existing.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    return {
      accessToken: this.signAccessToken(user),
      mustChangePassword: user.mustChangePassword,
      refreshToken: newRefresh.raw,
      refreshTokenExpiresAt: newRefresh.expiresAt,
    };
  }

  // Kills just the presented session, not every session for the user.
  async logout(rawRefreshToken: string): Promise<void> {
    const tokenHash = this.hashToken(rawRefreshToken);
    await this.prisma.refreshToken.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  // Only rows past their own expiry are purged — a revoked-but-not-yet-
  // expired row still has to stick around, since it's what lets refresh()
  // detect a stolen token being replayed and kill the whole family. Once a
  // row is past expiresAt it can never be used to refresh anyway (refresh()
  // rejects on expiry), so deleting it loses nothing.
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupExpiredRefreshTokens(): Promise<void> {
    const { count } = await this.prisma.refreshToken.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
    if (count > 0) {
      this.logger.log(`Purged ${count} expired refresh token(s)`);
    }
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.usersService.requestPasswordReset(email);
  }

  // The counter itself is bumped via Prisma's atomic increment rather than a
  // read-then-write, so concurrent wrong-password attempts against the same
  // account can't under-count each other and delay the lockout.
  private async registerFailedLogin(user: User): Promise<void> {
    const updated = await this.prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: { increment: 1 } },
      select: { failedLoginAttempts: true },
    });

    if (updated.failedLoginAttempts >= LOCKOUT_THRESHOLD) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { lockedUntil: new Date(Date.now() + LOCKOUT_DURATION_MS) },
      });
    }
  }

  private signAccessToken(user: SafeUser): string {
    return this.jwtService.sign({
      sub: user.id,
      role: user.role,
      tenantId: user.tenantId,
      mustChangePassword: user.mustChangePassword,
    });
  }

  private async issueRefreshToken(userId: string, familyId: string) {
    const raw = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

    const created = await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: this.hashToken(raw),
        familyId,
        expiresAt,
      },
    });

    return { id: created.id, raw, expiresAt };
  }

  // Refresh tokens are already high-entropy random values, not human
  // passwords — a fast hash is enough to protect the DB-at-rest copy, and
  // argon2's deliberate slowness would just tax every refresh call for no
  // real security benefit here.
  private hashToken(raw: string): string {
    return createHash('sha256').update(raw).digest('hex');
  }
}
