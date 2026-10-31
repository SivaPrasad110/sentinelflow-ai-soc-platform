import { Injectable } from '@nestjs/common';
import {
  MITRE_ATTACK_CATALOG,
  MITRE_ATTACK_TACTICS,
  MitreTechnique,
} from '@sentinelflow/shared';

@Injectable()
export class MitreAttackService {
  private readonly catalog: Map<string, MitreTechnique> = new Map();

  constructor() {
    for (const tech of MITRE_ATTACK_CATALOG) {
      this.catalog.set(tech.id.toUpperCase(), tech);
    }
  }

  /**
   * Get all supported tactics in Enterprise ATT&CK matrix
   */
  getTactics() {
    return MITRE_ATTACK_TACTICS;
  }

  /**
   * Get all supported catalog techniques
   */
  getAllTechniques(): MitreTechnique[] {
    return MITRE_ATTACK_CATALOG;
  }

  /**
   * Lookup a validated MITRE technique by ID (e.g. 'T1059.001')
   */
  getTechniqueById(id: string): MitreTechnique | undefined {
    return this.catalog.get(id.trim().toUpperCase());
  }

  /**
   * Validate that technique exists in the official catalog
   */
  isValidTechnique(techniqueId: string): boolean {
    return this.catalog.has(techniqueId.trim().toUpperCase());
  }

  /**
   * Find techniques matching a specific tactic
   */
  getTechniquesByTactic(tacticNameOrId: string): MitreTechnique[] {
    const term = tacticNameOrId.trim().toLowerCase();
    return MITRE_ATTACK_CATALOG.filter(
      (t) =>
        t.tactic.toLowerCase() === term ||
        t.tacticId.toLowerCase() === term,
    );
  }
}
