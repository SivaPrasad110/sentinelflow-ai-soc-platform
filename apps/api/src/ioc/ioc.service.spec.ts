import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { IocService } from './ioc.service';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { EventsGateway } from '../events/events.gateway';
import { IOCType, Severity } from '@prisma/client';

describe('IocService (Phase 6 Threat Intelligence IOCs)', () => {
  let service: IocService;
  let prismaMock: any;
  let auditMock: any;
  let eventsMock: any;

  const orgId = 'org-sentinel-corp';

  beforeEach(async () => {
    prismaMock = {
      indicatorOfCompromise: {
        findFirst: jest.fn(),
        findMany: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
    };

    auditMock = {
      log: jest.fn().mockResolvedValue({}),
    };

    eventsMock = {
      broadcastToOrg: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IocService,
        { provide: PrismaService, useValue: prismaMock },
        { provide: AuditService, useValue: auditMock },
        { provide: EventsGateway, useValue: eventsMock },
      ],
    }).compile();

    service = module.get<IocService>(IocService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('IOC Format Validation', () => {
    it('should accept valid IPv4 address', () => {
      expect(service.validateIocFormat(IOCType.IP, '198.51.100.45')).toBe(true);
    });

    it('should reject invalid IP address', () => {
      expect(service.validateIocFormat(IOCType.IP, '999.999.999.999')).toBe(false);
      expect(service.validateIocFormat(IOCType.IP, 'not-an-ip')).toBe(false);
    });

    it('should accept valid Domain name', () => {
      expect(service.validateIocFormat(IOCType.DOMAIN, 'malicious-c2.evil-corp.cc')).toBe(true);
    });

    it('should reject invalid Domain name', () => {
      expect(service.validateIocFormat(IOCType.DOMAIN, 'invalid_domain_name')).toBe(false);
    });

    it('should accept valid URL', () => {
      expect(service.validateIocFormat(IOCType.URL, 'https://evil-payload.site/beacon.bin')).toBe(true);
    });

    it('should reject invalid URL', () => {
      expect(service.validateIocFormat(IOCType.URL, 'ftp://missing-protocol')).toBe(false);
    });

    it('should accept valid SHA256 file hash', () => {
      const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      expect(service.validateIocFormat(IOCType.HASH_SHA256, sha256)).toBe(true);
    });

    it('should accept valid MD5 file hash', () => {
      const md5 = '098f6bcd4621d373cade4e832627b4f6';
      expect(service.validateIocFormat(IOCType.HASH_MD5, md5)).toBe(true);
    });

    it('should reject malformed file hash', () => {
      expect(service.validateIocFormat(IOCType.HASH_SHA256, 'too-short-hash')).toBe(false);
    });

    it('should accept valid Email indicator', () => {
      expect(service.validateIocFormat(IOCType.EMAIL, 'phisher@malicious-domain.org')).toBe(true);
    });
  });

  describe('create', () => {
    it('should throw BadRequestException for invalid indicator format', async () => {
      await expect(
        service.create(
          {
            type: IOCType.IP,
            value: 'invalid-ip-string',
          },
          orgId,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should create new indicator when valid and non-existing', async () => {
      prismaMock.indicatorOfCompromise.findFirst.mockResolvedValue(null);
      const mockCreated = {
        id: 'ioc-101',
        type: IOCType.IP,
        value: '185.220.101.5',
        confidence: 0.9,
        threatScore: 85,
        severity: Severity.HIGH,
        source: 'MANUAL',
        organizationId: orgId,
        firstSeen: new Date(),
        lastSeen: new Date(),
        tags: ['c2', 'tor-exit'],
        mitreTactics: ['Command and Control'],
        mitreTechniques: ['T1071.001'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      prismaMock.indicatorOfCompromise.create.mockResolvedValue(mockCreated);

      const result = await service.create(
        {
          type: IOCType.IP,
          value: '185.220.101.5',
          severity: Severity.HIGH,
          confidence: 0.9,
          threatScore: 85,
          tags: ['c2', 'tor-exit'],
        },
        orgId,
      );

      expect(result).toBeDefined();
      expect(result.id).toBe('ioc-101');
      expect(result.value).toBe('185.220.101.5');
      expect(eventsMock.broadcastToOrg).toHaveBeenCalledWith(orgId, 'ioc:created', expect.any(Object));
      expect(auditMock.log).toHaveBeenCalledWith(
        expect.objectContaining({
          organizationId: orgId,
          action: 'IOC_CREATE',
        }),
      );
    });

    it('should update existing indicator on duplicate (deduplication)', async () => {
      const existing = {
        id: 'ioc-existing-1',
        type: IOCType.DOMAIN,
        value: 'c2-beacon.evil.com',
        confidence: 0.7,
        threatScore: 60,
        severity: Severity.MEDIUM,
        tags: ['c2'],
        mitreTactics: [],
        mitreTechniques: [],
        organizationId: orgId,
        firstSeen: new Date(),
        lastSeen: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      prismaMock.indicatorOfCompromise.findFirst.mockResolvedValue(existing);
      prismaMock.indicatorOfCompromise.update.mockResolvedValue({
        ...existing,
        confidence: 0.95,
        threatScore: 90,
        severity: Severity.CRITICAL,
      });

      const result = await service.create(
        {
          type: IOCType.DOMAIN,
          value: 'c2-beacon.evil.com',
          confidence: 0.95,
          threatScore: 90,
          severity: Severity.CRITICAL,
        },
        orgId,
      );

      expect(prismaMock.indicatorOfCompromise.update).toHaveBeenCalled();
      expect(result.confidence).toBe(0.95);
    });
  });

  describe('findAll', () => {
    it('should query indicators scoped to organization or global with search filter', async () => {
      prismaMock.indicatorOfCompromise.findMany.mockResolvedValue([
        {
          id: 'ioc-1',
          type: IOCType.IP,
          value: '198.51.100.1',
          confidence: 0.8,
          severity: Severity.HIGH,
          organizationId: orgId,
          tags: [],
          mitreTactics: [],
          mitreTechniques: [],
          firstSeen: new Date(),
          lastSeen: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ]);

      const results = await service.findAll(orgId, { query: '198.51', type: IOCType.IP });
      expect(results).toHaveLength(1);
      expect(prismaMock.indicatorOfCompromise.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            organizationId: orgId,
            type: IOCType.IP,
          }),
        }),
      );
    });
  });
});
