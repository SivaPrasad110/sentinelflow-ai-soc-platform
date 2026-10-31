import { Injectable } from '@nestjs/common';
import {
  AlertSeverity,
  IndicatorOfCompromise,
  RiskScoreBreakdown,
} from '@sentinelflow/shared';

export interface RiskCalculationParams {
  severity: AlertSeverity;
  matchedIocs?: IndicatorOfCompromise[];
  mitreTactic?: string;
  mitreTechniqueId?: string;
  evidenceItems?: string[];
  threatFeedScore?: number;
}

@Injectable()
export class RiskScoringService {
  /**
   * Calculate transparent, explainable risk score (0 - 100)
   */
  calculate(params: RiskCalculationParams): RiskScoreBreakdown {
    const rationale: string[] = [];

    // 1. Base Severity Weight
    let baseSeverityScore = 15;
    switch (params.severity) {
      case 'CRITICAL':
        baseSeverityScore = 40;
        rationale.push('Critical severity base weight (+40 pts)');
        break;
      case 'HIGH':
        baseSeverityScore = 25;
        rationale.push('High severity base weight (+25 pts)');
        break;
      case 'MEDIUM':
        baseSeverityScore = 15;
        rationale.push('Medium severity base weight (+15 pts)');
        break;
      case 'LOW':
      default:
        baseSeverityScore = 5;
        rationale.push('Low severity base weight (+5 pts)');
        break;
    }

    // 2. Threat Intelligence & IOC Match Factor (up to 30 pts)
    let iocConfidenceScore = 0;
    if (params.matchedIocs && params.matchedIocs.length > 0) {
      // Get highest threat score / confidence among matched indicators
      let maxIocScore = 0;
      for (const ioc of params.matchedIocs) {
        const score = (ioc.threatScore || 50) * (ioc.confidence || 0.8);
        if (score > maxIocScore) maxIocScore = score;
      }
      // Scale into max 30 points
      iocConfidenceScore = Math.min(30, Math.round((maxIocScore / 100) * 30));
      rationale.push(
        `Correlated with ${params.matchedIocs.length} verified threat intelligence indicator(s) (+${iocConfidenceScore} pts)`,
      );
    } else if (params.threatFeedScore) {
      iocConfidenceScore = Math.min(30, Math.round((params.threatFeedScore / 100) * 30));
      rationale.push(`Threat feed reputation match (+${iocConfidenceScore} pts)`);
    }

    // 3. MITRE ATT&CK Tactic Impact Factor (up to 15 pts)
    let mitreImpactScore = 0;
    const tactic = (params.mitreTactic || '').toLowerCase();
    if (tactic.includes('credential') || tactic.includes('impact') || tactic.includes('ta0006') || tactic.includes('ta0040')) {
      mitreImpactScore = 15;
      rationale.push(`High-consequence MITRE tactic: ${params.mitreTactic} (+15 pts)`);
    } else if (
      tactic.includes('command') ||
      tactic.includes('lateral') ||
      tactic.includes('execution') ||
      tactic.includes('ta0002') ||
      tactic.includes('ta0008') ||
      tactic.includes('ta0011')
    ) {
      mitreImpactScore = 10;
      rationale.push(`Active intrusion MITRE tactic: ${params.mitreTactic} (+10 pts)`);
    } else if (params.mitreTactic) {
      mitreImpactScore = 5;
      rationale.push(`Identified MITRE tactic: ${params.mitreTactic} (+5 pts)`);
    }

    // 4. Correlated Evidence Artifacts Bonus (up to 15 pts)
    let evidenceBonus = 0;
    const evCount = params.evidenceItems?.length || 0;
    if (evCount > 0) {
      evidenceBonus = Math.min(15, evCount * 3);
      rationale.push(`Correlated ${evCount} distinct telemetry evidence artifact(s) (+${evidenceBonus} pts)`);
    }

    // Total Score
    const totalScore = Math.min(100, Math.max(0, baseSeverityScore + iocConfidenceScore + mitreImpactScore + evidenceBonus));

    // Determine Risk Level
    let riskLevel: AlertSeverity = 'LOW';
    if (totalScore >= 80) riskLevel = 'CRITICAL';
    else if (totalScore >= 60) riskLevel = 'HIGH';
    else if (totalScore >= 35) riskLevel = 'MEDIUM';

    return {
      baseSeverityScore,
      iocConfidenceScore,
      mitreImpactScore,
      evidenceBonus,
      totalScore,
      riskLevel,
      rationale,
    };
  }
}
