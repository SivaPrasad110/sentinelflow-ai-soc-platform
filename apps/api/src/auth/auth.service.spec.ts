import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import {
  UnauthorizedException,
  ForbiddenException,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { Role, Prisma } from '@prisma/client';

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
      organization: {
        findUnique: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
      },
      organizationMembership: {
        create: jest.fn(),
      },
      refreshSession: {
        create: jest.fn().mockResolvedValue({ id: 'sess-1' }),
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({ id: 'sess-1' }),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      $transaction: jest.fn().mockImplementation(async (callback) => {
        return callback(prismaMock);
      }),
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

  describe('Registration & Tenant Provisioning', () => {
    const registerDto = {
      email: 'alex.vance@sentinelflow.local',
      password: 'SecurePassword123!',
      name: 'Alex Vance',
      organizationName: 'Vance Security',
    };

    it('should successfully register a new user and organization within a single transaction', async () => {
      prismaMock.organization.create.mockResolvedValueOnce({
        id: 'org-vance-001',
        name: 'Vance Security',
        slug: 'vance-security',
      });

      prismaMock.user.create.mockResolvedValueOnce({
        id: 'USR-VANCE-001',
        email: 'alex.vance@sentinelflow.local',
        name: 'Alex Vance',
        createdAt: new Date('2026-11-01T12:00:00Z'),
      });

      prismaMock.organizationMembership.create.mockResolvedValueOnce({
        id: 'MEM-VANCE-001',
        userId: 'USR-VANCE-001',
        organizationId: 'org-vance-001',
        role: Role.ADMIN,
        organization: {
          id: 'org-vance-001',
          name: 'Vance Security',
          slug: 'vance-security',
        },
      });

      const result = await service.register(registerDto, {
        userAgent: 'JestTestRunner/1.0',
        ipAddress: '127.0.0.1',
      });

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('mock.jwt.access_token');
      expect(result.refreshToken).toBeDefined();
      expect(typeof result.refreshToken).toBe('string');
      expect(result.user.email).toBe(registerDto.email);
      expect(result.user.name).toBe(registerDto.name);
      expect(result.user.activeRole).toBe(Role.ADMIN);
      expect(result.user.activeOrganizationId).toBe('org-vance-001');
      expect(result.user.memberships).toHaveLength(1);
      expect(result.user.memberships[0].organizationSlug).toBe('vance-security');

      // Verify transaction boundary execution
      expect(prismaMock.$transaction).toHaveBeenCalledTimes(1);
      expect(prismaMock.organization.create).toHaveBeenCalledWith({
        data: {
          name: 'Vance Security',
          slug: 'vance-security',
        },
      });
      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          email: registerDto.email,
          name: registerDto.name,
          tenantId: 'org-vance-001',
          passwordHash: expect.any(String),
        }),
      });
      expect(prismaMock.organizationMembership.create).toHaveBeenCalledWith({
        data: {
          userId: 'USR-VANCE-001',
          organizationId: 'org-vance-001',
          role: Role.ADMIN,
        },
        include: { organization: true },
      });
      expect(prismaMock.refreshSession.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: 'USR-VANCE-001',
          tokenHash: expect.any(String),
          userAgent: 'JestTestRunner/1.0',
          ipAddress: '127.0.0.1',
          expiresAt: expect.any(Date),
        }),
      });
    });

    it('should reject duplicate email during fast pre-check before starting transaction', async () => {
      prismaMock.user.findUnique.mockResolvedValueOnce({
        id: 'USR-EXISTING',
        email: registerDto.email,
      });

      const promise = service.register(registerDto);
      await expect(promise).rejects.toThrow(ConflictException);
      await expect(promise).rejects.toThrow(
        'An account with this email address already exists.',
      );

      // Must not initiate transaction if pre-check fails
      expect(prismaMock.$transaction).not.toHaveBeenCalled();
    });

    it('should catch concurrent duplicate email race condition (P2002) in transaction and throw ConflictException (409)', async () => {
      const p2002EmailError = {
        code: 'P2002',
        meta: { target: ['email'] },
        message: 'Unique constraint failed on the fields: (email)',
      };

      prismaMock.$transaction.mockRejectedValueOnce(p2002EmailError);

      const promise = service.register(registerDto);
      await expect(promise).rejects.toThrow(ConflictException);
      await expect(promise).rejects.toThrow(
        'An account with this email address already exists.',
      );
    });

    it('should catch P2002 with string constraint name User_email_key and throw ConflictException (409)', async () => {
      const p2002ConstraintError = {
        code: 'P2002',
        meta: { target: 'User_email_key' },
        message: 'Unique constraint failed on the constraint: User_email_key',
      };

      prismaMock.$transaction.mockRejectedValueOnce(p2002ConstraintError);

      const promise = service.register(registerDto);
      await expect(promise).rejects.toThrow(ConflictException);
      await expect(promise).rejects.toThrow(
        'An account with this email address already exists.',
      );
    });

    it('should automatically disambiguate slug when base slug is detected in pre-check', async () => {
      prismaMock.organization.findUnique.mockResolvedValueOnce({
        id: 'org-existing-001',
        slug: 'vance-security',
      });

      prismaMock.organization.create.mockImplementation(async ({ data }: any) => ({
        id: 'org-vance-002',
        name: data.name,
        slug: data.slug,
      }));

      prismaMock.user.create.mockResolvedValueOnce({
        id: 'USR-VANCE-002',
        email: registerDto.email,
        name: registerDto.name,
        createdAt: new Date(),
      });

      prismaMock.organizationMembership.create.mockImplementation(async ({ data }: any) => ({
        id: 'MEM-VANCE-002',
        userId: data.userId,
        organizationId: data.organizationId,
        role: data.role,
        organization: {
          id: data.organizationId,
          name: registerDto.organizationName,
          slug: 'vance-security-disambiguated',
        },
      }));

      const result = await service.register(registerDto);

      expect(result).toBeDefined();
      expect(prismaMock.organization.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          name: 'Vance Security',
          slug: expect.stringMatching(/^vance-security-[a-f0-9]{6}$/),
        }),
      });
    });

    it('should recover from concurrent slug collision (P2002) via bounded retry strategy', async () => {
      const p2002SlugError = {
        code: 'P2002',
        meta: { target: ['slug'] },
        message: 'Unique constraint failed on the fields: (slug)',
      };

      let attemptCount = 0;
      prismaMock.$transaction.mockImplementation(async (callback: any) => {
        attemptCount++;
        if (attemptCount === 1) {
          throw p2002SlugError;
        }
        return callback({
          organization: {
            create: jest.fn().mockResolvedValue({
              id: 'org-vance-003',
              name: 'Vance Security',
              slug: 'vance-security-retry',
            }),
          },
          user: {
            create: jest.fn().mockResolvedValue({
              id: 'USR-VANCE-003',
              email: registerDto.email,
              name: registerDto.name,
              createdAt: new Date(),
            }),
          },
          organizationMembership: {
            create: jest.fn().mockResolvedValue({
              id: 'MEM-VANCE-003',
              userId: 'USR-VANCE-003',
              organizationId: 'org-vance-003',
              role: Role.ADMIN,
              organization: {
                id: 'org-vance-003',
                name: 'Vance Security',
                slug: 'vance-security-retry',
              },
            }),
          },
          refreshSession: {
            create: jest.fn().mockResolvedValue({ id: 'sess-3' }),
          },
        });
      });

      const result = await service.register(registerDto);

      expect(result).toBeDefined();
      expect(attemptCount).toBe(2);
      expect(result.user.activeOrganizationId).toBe('org-vance-003');
    });

    it('should throw ConflictException (409) when slug collision retries are exhausted', async () => {
      const p2002SlugError = {
        code: 'P2002',
        meta: { target: ['slug'] },
        message: 'Unique constraint failed on the fields: (slug)',
      };

      let attempts = 0;
      prismaMock.$transaction.mockImplementation(async () => {
        attempts++;
        throw p2002SlugError;
      });

      const promise = service.register(registerDto);
      await expect(promise).rejects.toThrow(ConflictException);
      await expect(promise).rejects.toThrow(
        'An organization with this name already exists. Please choose a different organization name.',
      );

      // Verified 5 bounded attempts
      expect(attempts).toBe(5);
    });

    it('should safely log and throw InternalServerErrorException (500) on unexpected database errors without leaking credentials', async () => {
      const unexpectedDbError = new Error('FATAL 57P01: terminating connection due to administrator command');
      prismaMock.$transaction.mockRejectedValueOnce(unexpectedDbError);

      const promise = service.register(registerDto);
      await expect(promise).rejects.toThrow(InternalServerErrorException);
      await expect(promise).rejects.toThrow(
        'An unexpected error occurred during account registration.',
      );
    });
  });
});
