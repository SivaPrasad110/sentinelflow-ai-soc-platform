import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ThreatIntelView } from '../components/dashboard/ThreatIntelView';
import { DetectionEngineView } from '../components/dashboard/DetectionEngineView';
import * as ApiModule from '../services/api';
import * as AuthContextModule from '../context/AuthContext';
import * as SocketContextModule from '../context/SocketContext';
import type {
  ThreatFeed,
  IndicatorOfCompromise,
  ThreatIntelStatsResponse,
  DetectionRule,
  SecurityFinding,
  MitreTechnique,
} from '@sentinelflow/shared';

const mockThreatStats: ThreatIntelStatsResponse = {
  totalIocs: 15,
  activeIocs: 15,
  feedCount: 3,
  iocsByType: {
    IP: 6,
    DOMAIN: 4,
    URL: 2,
    HASH_SHA256: 2,
    HASH_MD5: 1,
    EMAIL: 0,
  },
  iocsBySeverity: {
    CRITICAL: 5,
    HIGH: 6,
    MEDIUM: 3,
    LOW: 1,
  },
  totalFindings: 4,
  unresolvedFindings: 3,
  mitreCoverageCount: 8,
};

const mockFeeds: ThreatFeed[] = [
  {
    id: 'feed-1',
    name: 'Abuse.ch URLhaus (Malicious URLs)',
    feedUrl: 'https://urlhaus.abuse.ch/downloads/json_recent/',
    feedType: 'URLHAUS',
    format: 'JSON',
    enabled: true,
    itemCount: 42,
    status: 'COMPLETED',
    lastFetchedAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

const mockIocs: IndicatorOfCompromise[] = [
  {
    id: 'ioc-1',
    type: 'IP',
    value: '198.51.100.45',
    threatScore: 85,
    confidence: 0.9,
    severity: 'HIGH',
    source: 'ThreatFox',
    description: 'Cobalt Strike C2 server',
    mitreTactics: ['Command and Control'],
    mitreTechniques: ['T1071.001'],
    isActive: true,
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'ioc-2',
    type: 'DOMAIN',
    value: 'malicious-update.cc',
    threatScore: 95,
    confidence: 0.95,
    severity: 'CRITICAL',
    source: 'URLhaus',
    description: 'Malware delivery domain',
    mitreTactics: ['Initial Access'],
    mitreTechniques: ['T1566'],
    isActive: true,
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

const mockRules: DetectionRule[] = [
  {
    id: 'rule-1',
    name: 'Suspicious PowerShell Execution',
    description: 'Detects base64 encoded powershell',
    organizationId: 'org-1',
    severity: 'HIGH',
    ruleType: 'PATTERN',
    criteria: [{ field: 'title', operator: 'CONTAINS', value: 'PowerShell' }],
    mitreTactic: 'Execution',
    mitreTechnique: 'Command and Scripting Interpreter: PowerShell',
    mitreTechniqueId: 'T1059.001',
    enabled: true,
    triggerCount: 3,
    lastTriggeredAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

const mockFindings: SecurityFinding[] = [
  {
    id: 'find-1',
    organizationId: 'org-1',
    ruleId: 'rule-1',
    ruleName: 'Suspicious PowerShell Execution',
    title: '[Detection] Suspicious PowerShell: Encoded command',
    description: 'Triggered by suspicious alert',
    severity: 'HIGH',
    riskScore: 78,
    riskBreakdown: {
      baseSeverityScore: 25,
      iocConfidenceScore: 24,
      mitreImpactScore: 10,
      evidenceBonus: 9,
      totalScore: 78,
      riskLevel: 'HIGH',
      rationale: [
        'High severity base weight (+25 pts)',
        'Correlated with verified threat intel (+24 pts)',
        'Active intrusion MITRE tactic (+10 pts)',
      ],
    },
    evidence: {
      alertTitle: 'Encoded PowerShell command executed',
    },
    mitreTactic: 'Execution',
    mitreTechnique: 'PowerShell',
    mitreTechniqueId: 'T1059.001',
    fingerprint: 'fp-101',
    status: 'NEW',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

const mockMitreMatrix = [
  {
    id: 'TA0002',
    name: 'Execution',
    techniques: [
      {
        id: 'T1059.001',
        name: 'Command and Scripting Interpreter: PowerShell',
        tactic: 'Execution',
        tacticId: 'TA0002',
        description: 'Adversaries may use PowerShell commands to execute malicious scripts.',
      },
    ],
  },
];

describe('Phase 6: Threat Intelligence & Detection Engine UI', () => {
  beforeEach(() => {
    vi.spyOn(AuthContextModule, 'useAuth').mockReturnValue({
      user: { id: 'usr-1', email: 'analyst@sentinelflow.local', name: 'Analyst Jane' } as any,
      activeOrganization: { id: 'org-1', name: 'Sentinel Corp' } as any,
      activeRole: 'ANALYST',
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      switchOrganization: vi.fn(),
      refreshUserSession: vi.fn(),
    });

    vi.spyOn(SocketContextModule, 'useSocket').mockReturnValue({
      socket: { on: vi.fn(), off: vi.fn(), emit: vi.fn() } as any,
      isConnected: true,
    });

    vi.spyOn(ApiModule, 'getThreatIntelStats').mockResolvedValue(mockThreatStats);
    vi.spyOn(ApiModule, 'getThreatFeeds').mockResolvedValue(mockFeeds);
    vi.spyOn(ApiModule, 'getIocs').mockResolvedValue(mockIocs);
    vi.spyOn(ApiModule, 'syncThreatFeed').mockResolvedValue({ status: 'SUCCESS', indicatorsImported: 5 } as any);
    vi.spyOn(ApiModule, 'getDetectionRules').mockResolvedValue(mockRules);
    vi.spyOn(ApiModule, 'getFindings').mockResolvedValue(mockFindings);
    vi.spyOn(ApiModule, 'getMitreMatrix').mockResolvedValue(mockMitreMatrix);
    vi.spyOn(ApiModule, 'toggleDetectionRule').mockResolvedValue({ ...mockRules[0], enabled: false });
    vi.spyOn(ApiModule, 'promoteFindingToIncident').mockResolvedValue({ id: 'INC-ESCALATED-99' } as any);
  });

  describe('ThreatIntelView Component', () => {
    it('renders threat intelligence stats and feeds', async () => {
      render(<ThreatIntelView />);

      await waitFor(() => {
        expect(screen.getByText('Threat Intelligence Engine')).toBeInTheDocument();
        expect(screen.getByText('TOTAL INDICATORS')).toBeInTheDocument();
        expect(screen.getByText('Abuse.ch URLhaus (Malicious URLs)')).toBeInTheDocument();
        expect(screen.getByText('198.51.100.45')).toBeInTheDocument();
        expect(screen.getByText('malicious-update.cc')).toBeInTheDocument();
      });
    });

    it('triggers feed synchronization when clicking Sync Feed', async () => {
      render(<ThreatIntelView />);

      await waitFor(() => {
        expect(screen.getByText('Sync Feed')).toBeInTheDocument();
      });

      const syncBtn = screen.getByText('Sync Feed');
      fireEvent.click(syncBtn);

      await waitFor(() => {
        expect(ApiModule.syncThreatFeed).toHaveBeenCalledWith('feed-1');
      });
    });
  });

  describe('DetectionEngineView Component', () => {
    it('renders correlated findings with explainable risk score and rationale breakdown', async () => {
      render(<DetectionEngineView />);

      await waitFor(() => {
        expect(screen.getByText('Detection Engine & Correlated Findings')).toBeInTheDocument();
        expect(screen.getByText('[Detection] Suspicious PowerShell: Encoded command')).toBeInTheDocument();
        expect(screen.getByText('RISK 78/100')).toBeInTheDocument();
      });

      // Expand explainable risk breakdown
      const inspectBtn = screen.getByText('Inspect Risk Score Breakdown');
      fireEvent.click(inspectBtn);

      await waitFor(() => {
        expect(screen.getByText('EXPLAINABLE RISK FORMULA ANALYSIS')).toBeInTheDocument();
        expect(screen.getByText('+25 pts')).toBeInTheDocument();
        expect(screen.getByText('High severity base weight (+25 pts)')).toBeInTheDocument();
      });
    });

    it('supports one-click escalation of finding to formal incident', async () => {
      const mockOnIncidentCreated = vi.fn();
      render(<DetectionEngineView onIncidentCreated={mockOnIncidentCreated} />);

      await waitFor(() => {
        expect(screen.getByText('Escalate to Incident')).toBeInTheDocument();
      });

      const escalateBtn = screen.getByText('Escalate to Incident');
      fireEvent.click(escalateBtn);

      await waitFor(() => {
        expect(ApiModule.promoteFindingToIncident).toHaveBeenCalledWith('find-1');
        expect(mockOnIncidentCreated).toHaveBeenCalledWith('INC-ESCALATED-99');
      });
    });

    it('switches to MITRE ATT&CK Matrix navigator view', async () => {
      render(<DetectionEngineView />);

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /mitre att&ck matrix/i })).toBeInTheDocument();
      });

      const mitreTab = screen.getByRole('button', { name: /mitre att&ck matrix/i });
      fireEvent.click(mitreTab);

      await waitFor(() => {
        expect(screen.getByText('Enterprise ATT&CK Tactical Matrix')).toBeInTheDocument();
        expect(screen.getByText('T1059.001')).toBeInTheDocument();
      });
    });
  });
});
