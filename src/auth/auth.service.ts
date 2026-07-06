import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { User } from '../generated/prisma/client';
import * as argon2 from 'argon2';

type SafeUser = Omit<User, 'hashedPassword'>;

const DUMMY_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$GI8yFc6QCemSdwM0skhZvg$3elgnlxE0oIy891fIvSi8cabR0CpJgR2fGQ/xqKpOys';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<SafeUser> {
    const user = await this.usersService.findByEmail(email);

    const isPasswordValid = await argon2.verify(
      user?.hashedPassword ?? DUMMY_HASH,
      password,
    );

    if (!user || !isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { hashedPassword, ...userWithoutPassword } = user;

    return userWithoutPassword;
  }

  async login(user: SafeUser) {
    const payload = {
      sub: user.id,
      role: user.role,
      tenantId: user.tenantId,
      mustChangePassword: user.mustChangePassword,
    };
    return {
      access_token: this.jwtService.sign(payload),
      mustChangePassword: user.mustChangePassword,
    };
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.usersService.requestPasswordReset(email);
  }
}
