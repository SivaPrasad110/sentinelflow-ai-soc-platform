import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';
import { PrismaService } from '../prisma/prisma.service';

describe('HealthController', () => {
  let controller: HealthController;
  let prismaMock: { isHealthy: jest.Mock };

  beforeEach(async () => {
    prismaMock = {
      isHealthy: jest.fn().mockResolvedValue(true),
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
      ],
    }).compile();

    controller = module.get<HealthController>(HealthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should return system health status with connected database', async () => {
    const result = await controller.getHealth();
    expect(result).toBeDefined();
    expect(result.status).toBe('ok');
    expect(result.version).toBe('0.1.0');
    expect(result.services.api).toBe('healthy');
    expect(result.services.database).toBe('connected');
  });

  it('should return degraded status if database connection fails', async () => {
    prismaMock.isHealthy.mockResolvedValueOnce(false);
    const result = await controller.getHealth();
    expect(result.status).toBe('degraded');
    expect(result.services.database).toBe('disconnected');
  });
});
