import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  Headers,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser, AuthenticatedUser } from './decorators/current-user.decorator';
import { AuthResponse, UserProfile } from '@sentinelflow/shared';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private extractClientMetadata(req: Request) {
    return {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || (req.headers['x-forwarded-for'] as string),
    };
  }

  @Post('register')
  @ApiOperation({ summary: 'Register a new security analyst or administrator account and organization' })
  @ApiResponse({ status: 201, description: 'User and organization successfully registered' })
  @ApiResponse({ status: 409, description: 'Email address already in use' })
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponse> {
    const result = await this.authService.register(dto, this.extractClientMetadata(req));

    // Set secure HTTP-only cookie for refresh token
    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/v1/auth',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Rate limit: max 5 login attempts per minute per IP
  @ApiOperation({ summary: 'Authenticate user with corporate email and password' })
  @ApiResponse({ status: 200, description: 'Login successful. Returns access token and user profile.' })
  @ApiResponse({ status: 401, description: 'Invalid email or password' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthResponse> {
    const result = await this.authService.login(dto, this.extractClientMetadata(req));

    // Store refresh token in secure HTTP-only cookie
    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/v1/auth',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate and exchange refresh token for a new access token' })
  @ApiResponse({ status: 200, description: 'New token pair issued' })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
  async refresh(
    @Body() body: Partial<RefreshTokenDto>,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ accessToken: string }> {
    const token = body.refreshToken || req.cookies?.['refresh_token'];
    if (!token) {
      throw new Error('Refresh token not provided.');
    }

    const result = await this.authService.refresh({ refreshToken: token }, this.extractClientMetadata(req));

    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/v1/auth',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { accessToken: result.accessToken };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Revoke active refresh session and sign out' })
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ success: boolean }> {
    const token = req.cookies?.['refresh_token'];
    await this.authService.logout(token);
    res.clearCookie('refresh_token', { path: '/api/v1/auth' });
    return { success: true };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get profile and verified organization memberships of the authenticated user' })
  @ApiResponse({ status: 200, description: 'Authenticated user profile' })
  async getProfile(
    @CurrentUser() user: AuthenticatedUser,
    @Headers('x-organization-id') orgHint?: string,
  ): Promise<UserProfile> {
    return this.authService.getCurrentProfile(user.id, orgHint);
  }
}
