import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, ForbiddenException, ConflictException } from '@nestjs/common';
import * as argon2 from 'argon2';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { Role } from '@prisma/client';

describe('AuthService', () => {
  let service: AuthService;
  let prismaMock: any;
  let jwtMock: any;

  const validPassword = 'SecurePassword123!';
  let validHash: string;

  const mockUser = {
    id: 'USR-001',
    email: 'sarah.chen@sentinelflow.local',
    name: 'Sarah Chen',
    createdAt: new Date('2026-10-28T10:00:00Z'),
    memberships: [
      {
        id: 'MEM-001',
        userId: 'USR-001',
        organizationId: 'org-cyberdefense-001',
        role: Role.ANALYST,
        organization: {
          id: 'org-cyberdefense-001',
          name: 'CyberDefense SOC',
          slug: 'cyberdefense-soc',
        },
      },
    ],
  };

  beforeAll(async () => {
    validHash = await argon2.hash(validPassword, { type: argon2.argon2id });
  });

  beforeEach(async () => {
    prismaMock = {
      user: {
        findUnique: jest.fn().mockImplementation(({ where }) => {
          if (where.email === mockUser.email) {
            return Promise.resolve({ ...mockUser, passwordHash: validHash });
          }
          if (where.id === mockUser.id) {
            return Promise.resolve({ ...mockUser, passwordHash: validHash });
          }
          return Promise.resolve(null);
        }),
        create: jest.fn(),
      },
      refreshSession: {
        create: jest.fn().mockResolvedValue({ id: 'sess-1' }),
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({ id: 'sess-1' }),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
    };

    jwtMock = {
      sign: jest.fn().mockReturnValue('mock.jwt.access_token'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prismaMock },
        { provide: JwtService, useValue: jwtMock },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('test-jwt-secret'),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Login & Credential Verification', () => {
    it('should authenticate successfully with valid credentials and return token pair', async () => {
      const result = await service.login({
        email: 'sarah.chen@sentinelflow.local',
        password: validPassword,
      });

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('mock.jwt.access_token');
      expect(result.refreshToken).toBeDefined();
      expect(result.user.email).toBe(mockUser.email);
      expect(result.user.activeOrganizationId).toBe('org-cyberdefense-001');
      expect(result.user.activeRole).toBe(Role.ANALYST);
      expect(prismaMock.refreshSession.create).toHaveBeenCalled();
    });

    it('should reject invalid password with UnauthorizedException', async () => {
      await expect(
        service.login({
          email: 'sarah.chen@sentinelflow.local',
          password: 'WrongPassword123!',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should reject non-existent user with UnauthorizedException', async () => {
      await expect(
        service.login({
          email: 'ghost@nonexistent.local',
          password: 'AnyPassword123!',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should reject requested organization hint if user is not a member', async () => {
      await expect(
        service.login({
          email: 'sarah.chen@sentinelflow.local',
          password: validPassword,
          organizationIdHint: 'unauthorized-foreign-org-999',
        }),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe('Refresh Token Rotation & Revocation', () => {
    it('should rotate refresh token and issue new token pair', async () => {
      const validSession = {
        id: 'sess-active',
        userId: mockUser.id,
        tokenHash: 'hashed-token',
        revokedAt: null,
        expiresAt: new Date(Date.now() + 100000),
        user: mockUser,
      };

      prismaMock.refreshSession.findUnique.mockResolvedValueOnce(validSession);

      const result = await service.refresh({ refreshToken: 'valid-refresh-token' });

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('mock.jwt.access_token');
      expect(result.refreshToken).toBeDefined();
      // Verifies old session revocation (rotation)
      expect(prismaMock.refreshSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'sess-active' },
          data: expect.objectContaining({ revokedAt: expect.any(Date) }),
        }),
      );
      // Verifies creation of new rotated session
      expect(prismaMock.refreshSession.create).toHaveBeenCalled();
    });

    it('should reject expired or revoked refresh token with UnauthorizedException', async () => {
      const revokedSession = {
        id: 'sess-revoked',
        tokenHash: 'hash',
        revokedAt: new Date(), // Already revoked
        expiresAt: new Date(Date.now() + 100000),
      };

      prismaMock.refreshSession.findUnique.mockResolvedValueOnce(revokedSession);

      await expect(
        service.refresh({ refreshToken: 'revoked-token' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('Logout', () => {
    it('should mark refresh session as revoked', async () => {
      const result = await service.logout('user-refresh-token');
      expect(result.success).toBe(true);
      expect(prismaMock.refreshSession.updateMany).toHaveBeenCalled();
    });
  });
});
