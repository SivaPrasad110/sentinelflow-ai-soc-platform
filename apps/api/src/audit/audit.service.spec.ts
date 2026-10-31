import { Test, TestingModule } from '@nestjs/testing';
import { AuditService } from './audit.service';
import { PrismaService } from '../prisma/prisma.service';

describe('AuditService (Phase 5 Immutable Audit Logging)', () => {
  let service: AuditService;
  let prismaMock: any;

  const currentOrgId = 'org-sentinel-corp';

  beforeEach(async () => {
    prismaMock = {
      auditLog: {
        create: jest.fn().mockImplementation(({ data }) =>
          Promise.resolve({
            id: 'AUD-001',
            ...data,
            createdAt: new Date(),
          }),
        ),
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'AUD-001',
            organizationId: currentOrgId,
            action: 'AUTH_LOGIN',
            entityType: 'AUTH',
            userId: 'usr-1',
            userEmail: 'sarah.chen@sentinelflow.local',
            createdAt: new Date(),
          },
          {
            id: 'AUD-002',
            organizationId: currentOrgId,
            action: 'INCIDENT_ASSIGN',
            entityType: 'INCIDENT',
            entityId: 'INC-001',
            userId: 'usr-1',
            userEmail: 'sarah.chen@sentinelflow.local',
            createdAt: new Date(),
          },
        ]),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuditService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    service = module.get<AuditService>(AuditService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should create an append-only audit log entry', async () => {
    await service.log({
      organizationId: currentOrgId,
      userId: 'usr-1',
      userEmail: 'sarah.chen@sentinelflow.local',
      action: 'INCIDENT_CREATE',
      entityType: 'INCIDENT',
      entityId: 'INC-2026-001',
      details: { title: 'DDoS Attack Flagged' },
    });

    expect(prismaMock.auditLog.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        organizationId: currentOrgId,
        action: 'INCIDENT_CREATE',
        entityType: 'INCIDENT',
        entityId: 'INC-2026-001',
      }),
    });
  });

  it('should query audit logs strictly scoped to the tenant organization', async () => {
    const logs = await service.findByOrganization(currentOrgId, 50);

    expect(Array.isArray(logs)).toBe(true);
    expect(logs.length).toBe(2);
    expect(prismaMock.auditLog.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          organizationId: currentOrgId,
        }),
        take: 50,
      }),
    );
  });

  it('should support filtering audit logs by action', async () => {
    await service.findByOrganization(currentOrgId, 25, 'AUTH_LOGIN');

    expect(prismaMock.auditLog.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          organizationId: currentOrgId,
          action: 'AUTH_LOGIN',
        }),
        take: 25,
      }),
    );
  });
});
