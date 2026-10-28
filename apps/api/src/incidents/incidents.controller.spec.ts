import { Test, TestingModule } from '@nestjs/testing';
import { IncidentsController } from './incidents.controller';
import { IncidentsService } from './incidents.service';

describe('IncidentsController', () => {
  let controller: IncidentsController;
  let service: IncidentsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [IncidentsController],
      providers: [IncidentsService],
    }).compile();

    controller = module.get<IncidentsController>(IncidentsController);
    service = module.get<IncidentsService>(IncidentsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should return all active incidents', () => {
    const incidents = controller.findAll();
    expect(Array.isArray(incidents)).toBe(true);
    expect(incidents.length).toBeGreaterThan(0);
    expect(incidents[0]).toHaveProperty('id');
    expect(incidents[0]).toHaveProperty('severity');
  });

  it('should retrieve an incident by ID', () => {
    const incident = controller.findById('INC-2026-001');
    expect(incident).toBeDefined();
    expect(incident.id).toBe('INC-2026-001');
  });
});
