import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { AuthenticatedUser } from '../decorators/current-user.decorator';

export interface JwtPayload {
  sub: string;
  email: string;
  organizationId: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (req: Request) => {
          let token: string | null = null;
          if (req && req.cookies) {
            token = req.cookies['access_token'] || null;
          }
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey:
        configService.get<string>('JWT_SECRET') ||
        'development_sentinelflow_jwt_secret_change_in_production_min_32_chars',
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: JwtPayload): Promise<AuthenticatedUser> {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: {
        memberships: {
          include: { organization: true },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException('Authentication failed: user no longer exists.');
    }

    // Client may supply a tenant selection hint via headers
    const rawHint = req.headers['x-organization-id'] || req.headers['x-tenant-id'];
    const tenantHint = Array.isArray(rawHint) ? rawHint[0] : rawHint;

    const targetOrgId = tenantHint || payload.organizationId;

    // Verify requested organization against trusted server-side memberships
    const membership = user.memberships.find((m) => m.organizationId === targetOrgId);

    if (!membership) {
      throw new ForbiddenException(
        `Cross-tenant access rejected: user is not an authorized member of organization "${targetOrgId}".`,
      );
    }

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      organizationId: membership.organizationId,
      role: membership.role,
    };
  }
}
