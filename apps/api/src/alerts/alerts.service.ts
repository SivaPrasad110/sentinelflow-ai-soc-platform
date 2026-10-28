import { Injectable } from '@nestjs/common';
import { SecurityAlert } from '@sentinelflow/shared';

@Injectable()
export class AlertsService {
  private alerts: SecurityAlert[] = [
    {
      id: 'ALT-9821',
      title: 'PowerShell EncodedCommand Execution',
      description: 'Host WS-FIN-04 executed powershell.exe -enc with elevated permissions.',
      severity: 'CRITICAL',
      source: 'CrowdStrike Falcon EDR',
      detectedAt: new Date(Date.now() - 3600000).toISOString(),
      createdAt: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: 'ALT-9823',
      title: 'LSASS Memory Read Access',
      description: 'Unsigned binary attempted OpenProcess on lsass.exe process ID 684.',
      severity: 'CRITICAL',
      source: 'Microsoft Defender for Endpoint',
      detectedAt: new Date(Date.now() - 3550000).toISOString(),
      createdAt: new Date(Date.now() - 3550000).toISOString(),
    },
    {
      id: 'ALT-9844',
      title: 'AWS CloudTrail Root / Admin Console Access',
      description: 'ConsoleLogin event without MFA verification detected from unrecognized ASN.',
      severity: 'HIGH',
      source: 'AWS GuardDuty',
      detectedAt: new Date(Date.now() - 5400000).toISOString(),
      createdAt: new Date(Date.now() - 5400000).toISOString(),
    },
    {
      id: 'ALT-9810',
      title: 'Brute Force / Password Spray Attack',
      description: 'High volume of 401 Unauthorized responses from Okta identity provider.',
      severity: 'MEDIUM',
      source: 'Okta System Log',
      detectedAt: new Date(Date.now() - 14400000).toISOString(),
      createdAt: new Date(Date.now() - 14400000).toISOString(),
    },
  ];

  findAll(): SecurityAlert[] {
    return this.alerts;
  }

  ingest(alert: Partial<SecurityAlert>): SecurityAlert {
    const newAlert: SecurityAlert = {
      id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
      title: alert.title || 'Security Event',
      description: alert.description || '',
      severity: alert.severity || 'MEDIUM',
      source: alert.source || 'Generic SIEM',
      rawEvent: alert.rawEvent,
      detectedAt: alert.detectedAt || new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };
    this.alerts.unshift(newAlert);
    return newAlert;
  }
}
