import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';
import { PrismaService } from '../prisma/prisma.service';
import { N8nIntegrationService } from '../n8n/n8n.service';

describe('HealthController', () => {
  let controller: HealthController;
  let prismaMock: { isHealthy: jest.Mock };
  let n8nMock: { checkConnectivity: jest.Mock };

  beforeEach(async () => {
    prismaMock = {
      isHealthy: jest.fn().mockResolvedValue(true),
    };

    n8nMock = {
      checkConnectivity: jest.fn().mockResolvedValue('reachable'),
    };

    const module: TestingModule = await Test.createTestingModule({
      imports: [ConfigModule.forRoot({ isGlobal: true })],
      controllers: [HealthController],
      providers: [
        HealthService,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
        {
          provide: N8nIntegrationService,
          useValue: n8nMock,
        },
      ],
    }).compile();

    controller = module.get<HealthController>(HealthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should return system health status with connected database and reachable n8n', async () => {
    const result = await controller.getHealth();
    expect(result).toBeDefined();
    expect(result.status).toBe('ok');
    expect(result.version).toBe('0.1.0');
    expect(result.services.api).toBe('healthy');
    expect(result.services.database).toBe('connected');
    expect(result.services.n8n).toBe('reachable');
  });

  it('should return degraded status if database connection fails', async () => {
    prismaMock.isHealthy.mockResolvedValueOnce(false);
    const result = await controller.getHealth();
    expect(result.status).toBe('degraded');
    expect(result.services.database).toBe('disconnected');
  });

  it('should accurately reflect unreachable n8n connectivity', async () => {
    n8nMock.checkConnectivity.mockResolvedValueOnce('unreachable');
    const result = await controller.getHealth();
    expect(result.services.n8n).toBe('unreachable');
  });
});
