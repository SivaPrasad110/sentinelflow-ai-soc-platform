import { RiskScoringService } from './risk-scoring.service';
import { AlertSeverity } from '@sentinelflow/shared';

describe('RiskScoringService (Explainable Risk Scoring Engine)', () => {
  let service: RiskScoringService;

  beforeEach(() => {
    service = new RiskScoringService();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should calculate accurate score for Critical severity alert with IOC match and High MITRE impact', () => {
    const result = service.calculate({
      severity: 'CRITICAL',
      matchedIocs: [
        {
          id: 'ioc-1',
          type: 'IP',
          value: '198.51.100.99',
          confidence: 0.95,
          threatScore: 90,
          createdAt: new Date().toISOString(),
        },
      ],
      mitreTactic: 'Credential Access (TA0006)',
      evidenceItems: ['telemetry-1', 'telemetry-2', 'telemetry-3'],
    });

    expect(result.baseSeverityScore).toBe(40);
    expect(result.iocConfidenceScore).toBeGreaterThanOrEqual(25);
    expect(result.mitreImpactScore).toBe(15);
    expect(result.evidenceBonus).toBe(9); // 3 * 3
    expect(result.totalScore).toBeGreaterThanOrEqual(80);
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.rationale.length).toBeGreaterThan(3);
  });

  it('should calculate low risk for Low severity alert without IOCs', () => {
    const result = service.calculate({
      severity: 'LOW',
    });

    expect(result.baseSeverityScore).toBe(5);
    expect(result.iocConfidenceScore).toBe(0);
    expect(result.mitreImpactScore).toBe(0);
    expect(result.evidenceBonus).toBe(0);
    expect(result.totalScore).toBe(5);
    expect(result.riskLevel).toBe('LOW');
  });

  it('should clamp maximum score to 100 with all factors maxed', () => {
    const result = service.calculate({
      severity: 'CRITICAL',
      matchedIocs: [
        {
          id: 'ioc-1',
          type: 'HASH_SHA256',
          value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          confidence: 1.0,
          threatScore: 100,
          createdAt: new Date().toISOString(),
        },
      ],
      mitreTactic: 'Impact (TA0040)',
      evidenceItems: ['1', '2', '3', '4', '5', '6', '7', '8'],
    });

    expect(result.totalScore).toBeLessThanOrEqual(100);
    expect(result.riskLevel).toBe('CRITICAL');
  });
});
