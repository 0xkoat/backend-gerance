import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AuthService, TokenPair } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { Public } from './decorators/public.decorator';
import { SkipPasswordCheck } from './decorators/skip-password-check.decorator';

const REFRESH_TOKEN_COOKIE = 'refresh_token';
// Scoped to /api/auth so the browser never attaches it to unrelated routes.
const REFRESH_TOKEN_COOKIE_PATH = '/api/auth';

// tighter limit: 5 attempts per minute per IP.
@Throttle({ default: { limit: 5, ttl: 60000 } })
@UseGuards(ThrottlerGuard)
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
    );
    const tokens = await this.authService.login(user);
    this.setRefreshCookie(res, tokens);
    return this.toBody(tokens);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const rawToken = this.readRefreshCookie(req);
    const tokens = await this.authService.refresh(rawToken);
    this.setRefreshCookie(res, tokens);
    return this.toBody(tokens);
  }

  // No @Public(): logging out still requires a valid (possibly about-to-
  // expire) access token, same as any other authenticated route. Skips the
  // mustChangePassword gate so an account stuck in the forced-change flow
  // can still log out.
  @SkipPasswordCheck()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE] as string | undefined;
    if (rawToken) {
      await this.authService.logout(rawToken);
    }
    res.clearCookie(REFRESH_TOKEN_COOKIE, { path: REFRESH_TOKEN_COOKIE_PATH });
    return { message: 'Logged out' };
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    await this.authService.requestPasswordReset(forgotPasswordDto.email);

    return {
      message:
        'If an account exists with this email, your administrator has been notified.',
    };
  }

  private readRefreshCookie(req: Request): string {
    const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE] as string | undefined;
    if (!rawToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return rawToken;
  }

  private setRefreshCookie(res: Response, tokens: TokenPair): void {
    res.cookie(REFRESH_TOKEN_COOKIE, tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      // 'lax' assumes the frontend reaches this API same-site (e.g. via a
      // Next.js BFF proxy). A frontend calling this API directly cross-site
      // will need 'none' + secure (HTTPS) instead — revisit once the
      // frontend integration's actual topology is settled.
      sameSite: 'lax',
      path: REFRESH_TOKEN_COOKIE_PATH,
      expires: tokens.refreshTokenExpiresAt,
    });
  }

  private toBody(tokens: TokenPair) {
    return {
      access_token: tokens.accessToken,
      mustChangePassword: tokens.mustChangePassword,
    };
  }
}
