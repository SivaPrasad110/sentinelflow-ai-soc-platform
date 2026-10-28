import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Role } from '@prisma/client';
import { AuthResponse, UserProfile, OrganizationMembership as SharedMembership } from '@sentinelflow/shared';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly accessTokenExpiry = '15m';
  private readonly refreshTokenExpiryDays = 7;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private generateSecureToken(): string {
    return crypto.randomBytes(40).toString('hex');
  }

  private mapUserProfile(
    user: { id: string; email: string; name: string; createdAt: Date },
    activeOrgId: string,
    activeRole: Role,
    rawMemberships: Array<{
      id: string;
      organizationId: string;
      role: Role;
      organization: { id: string; name: string; slug: string };
    }>,
  ): UserProfile {
    const memberships: SharedMembership[] = rawMemberships.map((m) => ({
      id: m.id,
      organizationId: m.organizationId,
      organizationName: m.organization.name,
      organizationSlug: m.organization.slug,
      role: m.role as SharedMembership['role'],
    }));

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      activeOrganizationId: activeOrgId,
      activeRole: activeRole as UserProfile['activeRole'],
      memberships,
      createdAt: user.createdAt.toISOString(),
    };
  }

  async register(
    dto: RegisterDto,
    metadata?: { userAgent?: string; ipAddress?: string },
  ): Promise<AuthResponse & { refreshToken: string }> {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase().trim() },
    });

    if (existing) {
      throw new ConflictException('An account with this email address already exists.');
    }

    // 1. Hash password with Argon2id
    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    // 2. Create Organization, User, and Membership atomically
    const slug = dto.organizationName
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || `org-${Date.now()}`;

    const created = await this.prisma.$transaction(async (tx) => {
      const org = await tx.organization.create({
        data: {
          name: dto.organizationName.trim(),
          slug,
        },
      });

      const user = await tx.user.create({
        data: {
          email: dto.email.toLowerCase().trim(),
          name: dto.name.trim(),
          passwordHash,
          tenantId: org.id,
        },
      });

      const membership = await tx.organizationMembership.create({
        data: {
          userId: user.id,
          organizationId: org.id,
          role: Role.ADMIN,
        },
        include: { organization: true },
      });

      return { user, org, membership };
    });

    // 3. Issue Token Pair
    const accessToken = this.jwtService.sign(
      {
        sub: created.user.id,
        email: created.user.email,
        organizationId: created.org.id,
      },
      { expiresIn: this.accessTokenExpiry },
    );

    const rawRefreshToken = this.generateSecureToken();
    const tokenHash = this.hashToken(rawRefreshToken);
    const expiresAt = new Date(Date.now() + this.refreshTokenExpiryDays * 24 * 60 * 60 * 1000);

    await this.prisma.refreshSession.create({
      data: {
        userId: created.user.id,
        tokenHash,
        userAgent: metadata?.userAgent,
        ipAddress: metadata?.ipAddress,
        expiresAt,
      },
    });

    const userProfile = this.mapUserProfile(
      created.user,
      created.org.id,
      created.membership.role,
      [created.membership],
    );

    return {
      accessToken,
      refreshToken: rawRefreshToken,
      user: userProfile,
    };
  }

  async login(
    dto: LoginDto,
    metadata?: { userAgent?: string; ipAddress?: string },
  ): Promise<AuthResponse & { refreshToken: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase().trim() },
      include: {
        memberships: {
          include: { organization: true },
        },
      },
    });

    if (!user || !user.passwordHash) {
      this.logger.warn(`Failed login attempt for non-existent or unconfigured user: ${dto.email}`);
      throw new UnauthorizedException('Invalid email or password.');
    }

    const isValidPassword = await argon2.verify(user.passwordHash, dto.password);
    if (!isValidPassword) {
      this.logger.warn(`Failed password verification for user: ${user.email}`);
      throw new UnauthorizedException('Invalid email or password.');
    }

    if (!user.memberships || user.memberships.length === 0) {
      throw new ForbiddenException('Account is not associated with any active security organization.');
    }

    // Resolve target organization from hint if valid, else pick primary
    let activeMembership = user.memberships[0];
    if (dto.organizationIdHint) {
      const match = user.memberships.find((m) => m.organizationId === dto.organizationIdHint);
      if (!match) {
        throw new ForbiddenException(
          `User is not an authorized member of requested organization "${dto.organizationIdHint}".`,
        );
      }
      activeMembership = match;
    }

    // Generate short-lived Access Token
    const accessToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        organizationId: activeMembership.organizationId,
      },
      { expiresIn: this.accessTokenExpiry },
    );

    // Generate Refresh Token & store secure hash
    const rawRefreshToken = this.generateSecureToken();
    const tokenHash = this.hashToken(rawRefreshToken);
    const expiresAt = new Date(Date.now() + this.refreshTokenExpiryDays * 24 * 60 * 60 * 1000);

    await this.prisma.refreshSession.create({
      data: {
        userId: user.id,
        tokenHash,
        userAgent: metadata?.userAgent,
        ipAddress: metadata?.ipAddress,
        expiresAt,
      },
    });

    const userProfile = this.mapUserProfile(
      user,
      activeMembership.organizationId,
      activeMembership.role,
      user.memberships,
    );

    return {
      accessToken,
      refreshToken: rawRefreshToken,
      user: userProfile,
    };
  }

  async refresh(
    dto: RefreshTokenDto,
    metadata?: { userAgent?: string; ipAddress?: string },
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const tokenHash = this.hashToken(dto.refreshToken);

    const session = await this.prisma.refreshSession.findUnique({
      where: { tokenHash },
      include: {
        user: {
          include: {
            memberships: {
              include: { organization: true },
            },
          },
        },
      },
    });

    if (!session || session.revokedAt !== null || session.expiresAt < new Date()) {
      this.logger.warn('Invalid or expired refresh token presented.');
      throw new UnauthorizedException('Invalid or expired refresh token. Please sign in again.');
    }

    // Token Rotation: revoke current session
    await this.prisma.refreshSession.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });

    const user = session.user;
    const activeMembership = user.memberships[0];

    // Issue new Token Pair
    const accessToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        organizationId: activeMembership.organizationId,
      },
      { expiresIn: this.accessTokenExpiry },
    );

    const newRawRefreshToken = this.generateSecureToken();
    const newTokenHash = this.hashToken(newRawRefreshToken);
    const expiresAt = new Date(Date.now() + this.refreshTokenExpiryDays * 24 * 60 * 60 * 1000);

    await this.prisma.refreshSession.create({
      data: {
        userId: user.id,
        tokenHash: newTokenHash,
        userAgent: metadata?.userAgent,
        ipAddress: metadata?.ipAddress,
        expiresAt,
      },
    });

    return {
      accessToken,
      refreshToken: newRawRefreshToken,
    };
  }

  async logout(refreshToken?: string): Promise<{ success: boolean }> {
    if (refreshToken) {
      const tokenHash = this.hashToken(refreshToken);
      await this.prisma.refreshSession.updateMany({
        where: { tokenHash, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }
    return { success: true };
  }

  async getCurrentProfile(userId: string, requestedOrgId?: string): Promise<UserProfile> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        memberships: {
          include: { organization: true },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException('User profile not found.');
    }

    let activeMembership = user.memberships[0];
    if (requestedOrgId) {
      const match = user.memberships.find((m) => m.organizationId === requestedOrgId);
      if (match) activeMembership = match;
    }

    return this.mapUserProfile(
      user,
      activeMembership.organizationId,
      activeMembership.role,
      user.memberships,
    );
  }
}
