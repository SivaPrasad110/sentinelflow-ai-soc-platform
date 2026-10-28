import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';
import { PrismaService } from '../../prisma/prisma.service';
import { Role } from '@prisma/client';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let prismaMock: any;

  const mockUser = {
    id: 'USR-001',
    email: 'analyst@sentinelflow.local',
    name: 'Sarah Chen',
    memberships: [
      {
        id: 'MEM-001',
        userId: 'USR-001',
        organizationId: 'org-authorized-1',
        role: Role.ANALYST,
        organization: { id: 'org-authorized-1', name: 'Authorized SOC', slug: 'auth-soc' },
      },
      {
        id: 'MEM-002',
        userId: 'USR-001',
        organizationId: 'org-authorized-2',
        role: Role.ADMIN,
        organization: { id: 'org-authorized-2', name: 'Secondary SOC', slug: 'sec-soc' },
      },
    ],
  };

  beforeEach(async () => {
    prismaMock = {
      user: {
        findUnique: jest.fn().mockImplementation(({ where }) => {
          if (where.id === mockUser.id) {
            return Promise.resolve(mockUser);
          }
          return Promise.resolve(null);
        }),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        { provide: PrismaService, useValue: prismaMock },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('test-jwt-secret'),
          },
        },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
  });

  it('should validate and resolve authenticated user with authorized organization membership', async () => {
    const mockReq = { headers: {} } as any;
    const payload = { sub: 'USR-001', email: 'analyst@sentinelflow.local', organizationId: 'org-authorized-1' };

    const result = await strategy.validate(mockReq, payload);

    expect(result).toBeDefined();
    expect(result.id).toBe('USR-001');
    expect(result.organizationId).toBe('org-authorized-1');
    expect(result.role).toBe(Role.ANALYST);
  });

  it('should allow switching organization if user is an authorized member of hint org', async () => {
    const mockReq = {
      headers: { 'x-organization-id': 'org-authorized-2' },
    } as any;
    const payload = { sub: 'USR-001', email: 'analyst@sentinelflow.local', organizationId: 'org-authorized-1' };

    const result = await strategy.validate(mockReq, payload);

    expect(result.organizationId).toBe('org-authorized-2');
    expect(result.role).toBe(Role.ADMIN);
  });

  it('should reject client x-tenant-id header hint if user is NOT a member of that organization', async () => {
    const mockReq = {
      headers: { 'x-tenant-id': 'unauthorized-foreign-tenant-999' },
    } as any;
    const payload = { sub: 'USR-001', email: 'analyst@sentinelflow.local', organizationId: 'org-authorized-1' };

    await expect(strategy.validate(mockReq, payload)).rejects.toThrow(ForbiddenException);
  });

  it('should throw UnauthorizedException if user no longer exists', async () => {
    const mockReq = { headers: {} } as any;
    const payload = { sub: 'DELETED-USER', email: 'deleted@user.local', organizationId: 'org-1' };

    await expect(strategy.validate(mockReq, payload)).rejects.toThrow(UnauthorizedException);
  });
});
