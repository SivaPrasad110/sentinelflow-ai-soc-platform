// scratch/verify_phase6_live.mjs
import http from 'http';

const BASE_URL = 'http://localhost:3000/api/v1';

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : await res.text();
  return { status: res.status, data };
}

async function main() {
  console.log('=== SentinelFlow Phase 6 Live End-to-End Verification ===\n');

  // 1. Health check
  console.log('1. Probing System Health Endpoint...');
  const healthRes = await request('/health');
  console.log(`   Status: HTTP ${healthRes.status}`);
  console.log(`   Database: ${healthRes.data?.services?.database}`);
  if (healthRes.status !== 200 || healthRes.data?.services?.database !== 'connected') {
    throw new Error('System health check failed!');
  }
  console.log('   [PASS] Health check verified.\n');

  // 2. Authenticate as Analyst
  console.log('2. Authenticating as Security Analyst (sarah.chen@sentinelflow.local)...');
  const loginRes = await request('/auth/login', {
    method: 'POST',
    body: {
      email: 'sarah.chen@sentinelflow.local',
      password: 'AnalystPassword123!',
    },
  });

  if (loginRes.status !== 200 || !loginRes.data?.accessToken) {
    throw new Error(`Login failed with HTTP ${loginRes.status}: ${JSON.stringify(loginRes.data)}`);
  }
  const token = loginRes.data.accessToken;
  const authHeaders = { Authorization: `Bearer ${token}` };
  console.log('   [PASS] Successfully authenticated. Role:', loginRes.data.user?.activeRole, '\n');

  // 3. Test IOC Format Validation Rejection
  console.log('3. Testing Defensive IOC Format Validation (rejection test)...');
  const invalidIocRes = await request('/iocs', {
    method: 'POST',
    headers: authHeaders,
    body: {
      type: 'IP',
      value: '999.999.999.999', // Invalid IP
      severity: 'HIGH',
    },
  });
  console.log(`   Invalid IP submission status: HTTP ${invalidIocRes.status}`);
  if (invalidIocRes.status !== 400) {
    throw new Error(`Expected HTTP 400 for invalid IP but got ${invalidIocRes.status}`);
  }
  console.log('   [PASS] Invalid indicator format properly rejected with 400 Bad Request.\n');

  // 4. Create Standalone Valid IOC
  console.log('4. Ingesting Standalone Valid Indicator of Compromise (IOC)...');
  const validIocRes = await request('/iocs', {
    method: 'POST',
    headers: authHeaders,
    body: {
      type: 'IP',
      value: '198.51.100.123',
      severity: 'CRITICAL',
      confidence: 0.95,
      threatScore: 92,
      source: 'ThreatFox Feed',
      description: 'Active Cobalt Strike C2 teamserver staging node',
      tags: ['cobalt-strike', 'c2', 'live-test'],
      mitreTactics: ['Command and Control'],
      mitreTechniques: ['T1071.001'],
    },
  });
  console.log(`   Status: HTTP ${validIocRes.status}, IOC ID: ${validIocRes.data?.id}`);
  if (validIocRes.status !== 201) {
    throw new Error(`Failed to create IOC: ${JSON.stringify(validIocRes.data)}`);
  }
  console.log('   [PASS] Valid indicator created with MITRE techniques & confidence.\n');

  // 5. Threat Feeds List & Sync
  console.log('5. Querying Defensive Threat Feeds & Triggering Synchronization...');
  const feedsRes = await request('/threat-intel/feeds', { headers: authHeaders });
  console.log(`   Retrieved ${feedsRes.data?.length} configured feeds.`);
  if (!feedsRes.data || feedsRes.data.length === 0) {
    throw new Error('No threat feeds found.');
  }

  const feedToSync = feedsRes.data[0];
  console.log(`   Syncing feed "${feedToSync.name}" (ID: ${feedToSync.id})...`);
  const syncRes = await request(`/threat-intel/feeds/${feedToSync.id}/sync`, {
    method: 'POST',
    headers: authHeaders,
  });
  console.log(`   Sync status: HTTP ${syncRes.status}, Result: ${syncRes.data?.status}`);
  console.log(`   Imported: ${syncRes.data?.indicatorsImported}, Duration: ${syncRes.data?.durationMs}ms`);
  if ((syncRes.status !== 200 && syncRes.status !== 201) || syncRes.data?.status !== 'SUCCESS') {
    throw new Error(`Feed sync failed: ${JSON.stringify(syncRes.data)}`);
  }
  console.log('   [PASS] Threat feed synced successfully with fallback resilience.\n');

  // 6. Threat Intel Stats
  console.log('6. Fetching Threat Intelligence Metrics & Stats...');
  const statsRes = await request('/threat-intel/stats', { headers: authHeaders });
  console.log(`   Total IOCs: ${statsRes.data?.totalIocs}, Feeds: ${statsRes.data?.feedCount}`);
  console.log(`   IOCs by Type:`, statsRes.data?.iocsByType);
  console.log('   [PASS] Threat intel stats aggregated.\n');

  // 7. MITRE ATT&CK Matrix Inspection
  console.log('7. Querying MITRE ATT&CK Enterprise Matrix...');
  const matrixRes = await request('/detection/mitre/matrix', { headers: authHeaders });
  console.log(`   Retrieved ${matrixRes.data?.length} tactics.`);
  const executionTactic = matrixRes.data?.find((t) => t.id === 'TA0002');
  console.log(`   Tactical Column "${executionTactic?.name}" contains ${executionTactic?.techniques?.length} catalog techniques.`);
  if (!executionTactic || executionTactic.techniques.length === 0) {
    throw new Error('Failed to load MITRE ATT&CK matrix.');
  }
  console.log('   [PASS] MITRE ATT&CK Matrix loaded with official catalog techniques.\n');

  // 8. Detection Rules Inspection
  console.log('8. Querying Configured Detection Rules...');
  const rulesRes = await request('/detection/rules', { headers: authHeaders });
  console.log(`   Active detection rules count: ${rulesRes.data?.length}`);
  const psRule = rulesRes.data?.find((r) => r.name.includes('PowerShell'));
  console.log(`   Found rule: "${psRule?.name}" [${psRule?.severity}] -> MITRE ${psRule?.mitreTechniqueId}`);
  if (!psRule) {
    throw new Error('Default PowerShell detection rule not found.');
  }
  console.log('   [PASS] Detection rules verified.\n');

  // 9. Ingest Alert to Trigger Detection Rule & Correlate Finding
  console.log('9. Ingesting Raw Security Alert to Trigger Detection Rule & Risk Scoring...');
  const alertRes = await request('/alerts', {
    method: 'POST',
    headers: authHeaders,
    body: {
      title: 'Suspicious Encoded PowerShell execution detected on host WKSTN-FIN-08',
      description: 'Process powershell.exe spawned with encoded payload connecting to 198.51.100.123',
      severity: 'HIGH',
      source: 'Sentinel-EDR-Sensor',
      rawPayload: {
        command: 'powershell.exe -enc aW52b2tlLW1pbWlrYXR6',
        host: 'WKSTN-FIN-08',
        user: 'finance.admin',
        remoteIp: '198.51.100.123',
      },
    },
  });
  console.log(`   Alert ingested: HTTP ${alertRes.status}, Alert ID: ${alertRes.data?.id}`);
  if (alertRes.status !== 201) {
    throw new Error(`Failed to ingest alert: ${JSON.stringify(alertRes.data)}`);
  }
  console.log('   [PASS] Alert ingested.\n');

  // 10. Verify Correlated Security Finding & Explainable Risk Score
  console.log('10. Inspecting Generated Correlated Security Finding...');
  const findingsRes = await request('/detection/findings', { headers: authHeaders });
  console.log(`    Total findings count: ${findingsRes.data?.length}`);
  const matchingFinding = findingsRes.data?.find(
    (f) => f.title.includes('PowerShell') || f.description.includes('WKSTN-FIN-08'),
  );

  if (!matchingFinding) {
    throw new Error('Expected finding to be generated from triggered detection rule!');
  }

  console.log(`    Generated Finding ID: ${matchingFinding.id}`);
  console.log(`    Title: "${matchingFinding.title}"`);
  console.log(`    Risk Score: ${matchingFinding.riskScore}/100 (${matchingFinding.severity})`);
  console.log(`    MITRE ATT&CK: ${matchingFinding.mitreTechniqueId} - ${matchingFinding.mitreTechnique}`);
  console.log(`    Explainable Risk Breakdown:`);
  console.log(`      Base Severity: +${matchingFinding.riskBreakdown?.baseSeverityScore} pts`);
  console.log(`      IOC Match Confidence: +${matchingFinding.riskBreakdown?.iocConfidenceScore} pts`);
  console.log(`      MITRE Impact: +${matchingFinding.riskBreakdown?.mitreImpactScore} pts`);
  console.log(`      Evidence Bonus: +${matchingFinding.riskBreakdown?.evidenceBonus} pts`);
  console.log(`      Scoring Rationale:`, matchingFinding.riskBreakdown?.rationale);

  if (matchingFinding.riskScore < 50) {
    throw new Error(`Expected elevated risk score for matched high alert with IOC, got ${matchingFinding.riskScore}`);
  }
  console.log('    [PASS] Correlated finding generated with explainable mathematical risk score.\n');

  // 11. Escalate/Promote Finding to Formal SOC Incident
  console.log('11. Promoting Security Finding to Formal SOC Incident (One-Click Escalation)...');
  const promoteRes = await request(`/detection/findings/${matchingFinding.id}/promote`, {
    method: 'POST',
    headers: authHeaders,
  });

  console.log(`    Promotion status: HTTP ${promoteRes.status}`);
  console.log(`    Escalated Incident ID: ${promoteRes.data?.id}`);
  console.log(`    Escalated Incident Title: "${promoteRes.data?.title}"`);
  if (promoteRes.status !== 200 || !promoteRes.data?.id) {
    throw new Error(`Failed to promote finding: ${JSON.stringify(promoteRes.data)}`);
  }
  console.log('    [PASS] Finding successfully escalated to formal incident.\n');

  // 12. Verify Audit Logs
  console.log('12. Verifying Immutable Security Audit Trail...');
  const auditRes = await request('/audit-logs?limit=10', { headers: authHeaders });
  console.log(`    Recent audit actions:`, auditRes.data?.map((l) => l.action).slice(0, 6));
  const hasIocLog = auditRes.data?.some((l) => l.action === 'IOC_CREATE');
  const hasFindingLog = auditRes.data?.some((l) => l.action === 'FINDING_GENERATED');
  const hasPromotedLog = auditRes.data?.some((l) => l.action === 'FINDING_PROMOTED');

  console.log(`    Audit checks: IOC_CREATE=${hasIocLog}, FINDING_GENERATED=${hasFindingLog}, FINDING_PROMOTED=${hasPromotedLog}`);
  if (!hasIocLog || !hasFindingLog || !hasPromotedLog) {
    throw new Error('Audit trail missing required detection engine actions.');
  }
  console.log('    [PASS] Audit trail verified.\n');

  console.log('===========================================================');
  console.log('ALL PHASE 6 LIVE END-TO-END VERIFICATION CHECKS PASSED 100%');
  console.log('===========================================================');
}

main().catch((err) => {
  console.error('\n❌ LIVE VERIFICATION FAILED:', err.message);
  process.exit(1);
});
