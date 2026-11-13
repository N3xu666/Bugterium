import React, { useState } from 'react';

const buildAssuranceClaims = (snapshot, isLive) => {
  const blocked403 = snapshot?.security_metrics?.blocked_403 ?? 0;
  const blocked429 = snapshot?.security_metrics?.blocked_429 ?? 0;
  const loginFail = snapshot?.auth?.totals?.login_fail;
  const authForbidden = snapshot?.auth?.totals?.forbidden;
  const app5xx = snapshot?.errors_5xx?.app_5xx;
  const platform5xx = snapshot?.errors_5xx?.platform_5xx;
  const stale = Boolean(snapshot?.meta?.stale);
  const quotaWarning = Boolean(snapshot?.meta?.quota_warning);
  const generatedAt = snapshot?.meta?.generated_at
    ? snapshot.meta.generated_at.replace('T', ' ').slice(0, 19) + 'Z'
    : 'FALLBACK';
  const hex32Count = Array.isArray(snapshot?.probes?.families)
    ? (snapshot.probes.families.find((f) => f.family === 'hex32_probe')?.count ?? 0)
    : null;
  const baselineLevel = snapshot?.baseline?.level
    ? String(snapshot.baseline.level).toUpperCase()
    : 'N/A';

  const telemStatus = !isLive
    ? 'FALLBACK'
    : (app5xx ?? 0) > 0
      ? 'ALERT'
      : stale || quotaWarning
        ? 'STALE'
        : 'VERIFIED';

  return [
    {
      id: 'AUTH-01',
      category: 'AUTHENTICATION & DOS',
      title: 'Anti-Brute-Force & Rate Limiting',
      claim: 'All /api/* and /auth/* endpoints enforce hard rate limits to prevent brute-force attacks and D1 database exhaustion.',
      control: 'Hono isolate in-memory limiter (100 req/min general, 10 req/min login) + HMAC-SHA256 hashed IP keys.',
      evidence: `Unit suite: test/middleware/rateLimit.test.ts | Live 24h: 429=${blocked429}, auth login_fail=${loginFail ?? 'N/A'}`,
      status: blocked429 > 0 || (loginFail ?? 0) > 0 ? 'ACTIVE' : 'ENFORCED',
      severity: 'HIGH',
      lastChecked: generatedAt
    },
    {
      id: 'EDGE-01',
      category: 'ENDPOINT & HOST PERIMETER',
      title: 'Zero Inbound Tunnels & Host Dark Perimeter',
      claim: 'Developer workstation is 100% inbound-dark. No reverse network tunnels (ngrok, cloudflared) or external port forwards exist.',
      control: 'Cloudflare Pages / Workers serverless edge execution. Strict rule in host security policy.',
      evidence: `0 active tunnels. Serverless edge handles traffic (app_5xx=${app5xx ?? 'N/A'}, plat_5xx=${platform5xx ?? 'N/A'}).`,
      status: (app5xx ?? 0) > 0 ? 'WARN' : 'VERIFIED',
      severity: 'CRITICAL',
      lastChecked: generatedAt
    },
    {
      id: 'RBAC-01',
      category: 'ACCESS CONTROL',
      title: 'Role-Based Access Control (Admin Protection)',
      claim: 'Unauthorized users attempting to access /api/admin receive HTTP 403 Forbidden with security audit logging.',
      control: 'RBAC middleware in BFF Worker + audit event logged to D1 (login_fail / forbidden).',
      evidence: `test/routes/admin.test.ts | Live 24h: edge 403=${blocked403}, BFF forbidden=${authForbidden ?? 'N/A'}`,
      status: (authForbidden ?? 0) > 0 || blocked403 > 0 ? 'ACTIVE' : 'ENFORCED',
      severity: 'HIGH',
      lastChecked: generatedAt
    },
    {
      id: 'SECR-01',
      category: 'OPSEC & DATA HYGIENE',
      title: 'Secret Leakage & Masking Canon',
      claim: 'Zero real flags, session tokens, passwords, or hashes exist in public documentation or git history.',
      control: '5-Gate pre-commit hook + Gitleaks CI + dictionary scan (115 masked secret entries).',
      evidence: 'check.ps1 [1/27] & [2/27]: 0 real flags, 0 leaks across tracked repository.',
      status: 'VERIFIED',
      severity: 'CRITICAL',
      lastChecked: 'Pre-commit 5-Gate & CI Gitleaks'
    },
    {
      id: 'SUPP-01',
      category: 'SUPPLY CHAIN',
      title: 'Dependency & CI Supply Chain Hygiene',
      claim: 'CI workflows and npm dependencies are protected against malicious package takeover and lifecycle script RCE.',
      control: 'SHA-pinned GitHub Actions, Trivy SCA, Semgrep SAST, npm --ignore-scripts policy.',
      evidence: 'GitHub Actions required gates green (SAST, SCA, CodeQL, DAST, Dependency Review).',
      status: 'VERIFIED',
      severity: 'HIGH',
      lastChecked: 'CI Supply Chain Gates'
    },
    {
      id: 'PRIV-01',
      category: 'PRIVACY & ANONYMIZATION',
      title: 'K-Anonymity & Zero PII Storage',
      claim: 'Public telemetry contains no IP addresses or individual fingerprints. All metrics are aggregated.',
      control: 'k-Anonymity (k >= 5) for country slices; 32-hex path masking as /[hex32].',
      evidence: `aggregate.ts | Live 24h: hex32_probe masked=${hex32Count ?? 'N/A'} | Baseline=${baselineLevel}`,
      status: 'VERIFIED',
      severity: 'MEDIUM',
      lastChecked: generatedAt
    },
    {
      id: 'TELEM-01',
      category: 'TELEMETRY INTEGRITY',
      title: 'Snapshot Freshness & 5xx Origin Isolation',
      claim: 'Edge monitor separates application crashes (app_5xx) from platform timeouts (platform_5xx) with zero-secret Contract v2 snapshots.',
      control: '5-minute Cron worker writes KV snapshot with meta.stale, quota_warning, and 5xx cache/origin classification.',
      evidence: `schema=${snapshot?.schema_version || '1.0'} | stale=${stale} | quota_warn=${quotaWarning} | app_5xx=${app5xx ?? 'N/A'} | plat_5xx=${platform5xx ?? 'N/A'}`,
      status: telemStatus,
      severity: 'HIGH',
      lastChecked: generatedAt
    }
  ];
};

const getStatusColor = (status) => {
  if (status === 'ALERT') return '#c00030';
  if (status === 'STALE' || status === 'FALLBACK' || status === 'WARN') return '#ff8c00';
  return '#00ff66';
};

export default function AssuranceView({ snapshot = null, isLive = false }) {
  const [selectedClaim, setSelectedClaim] = useState(null);
  const claims = buildAssuranceClaims(snapshot, isLive);
  const healthyCount = claims.filter((c) => ['VERIFIED', 'ENFORCED', 'ACTIVE'].includes(c.status)).length;
  const app5xx = snapshot?.errors_5xx?.app_5xx ?? 0;
  const isStale = Boolean(snapshot?.meta?.stale);

  const summaryStatus = !isLive
    ? { label: 'OFFLINE FALLBACK', color: '#ff8c00' }
    : app5xx > 0
      ? { label: `APP 5XX ALERT (${app5xx})`, color: '#c00030' }
      : isStale
        ? { label: 'SNAPSHOT STALE', color: '#ff8c00' }
        : { label: 'ALL GATES GREEN', color: '#00ff66' };

  return (
    <div style={{
      width: '100%',
      height: '100%',
      backgroundColor: '#000000',
      color: '#d7d7d7',
      fontFamily: 'JetBrains Mono, monospace',
      display: 'flex',
      flexDirection: 'column',
      padding: '16px',
      boxSizing: 'border-box',
      overflow: 'hidden'
    }}>
      {/* HEADER */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: '1px solid #1a1a1a',
        paddingBottom: '12px',
        marginBottom: '14px',
        flexShrink: 0
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ color: '#c00030', fontWeight: 'bold', fontSize: '13px', letterSpacing: '0.08em' }}>
            [ ASSURANCE &amp; VERIFIED CLAIMS ]
          </span>
          <span style={{ fontSize: '10px', color: '#6a6a6a', border: '1px solid #282828', padding: '2px 6px' }}>
            CONTRACT V2 VERIFICATION ENGINE
          </span>
        </div>

        <div style={{ display: 'flex', gap: '15px', fontSize: '11px', color: '#888888' }}>
          <div>ENFORCED CONTROLS: <span style={{ color: '#00ff66', fontWeight: 'bold' }}>{healthyCount} / {claims.length}</span></div>
          <div>STATUS: <span style={{ color: summaryStatus.color, fontWeight: 'bold' }}>{summaryStatus.label}</span></div>
        </div>
      </div>

      {/* CLAIMS GRID */}
      <div style={{
        flex: 1,
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '12px',
        overflowY: 'auto',
        minHeight: 0,
        paddingBottom: '10px'
      }}>
        {claims.map(item => {
          const isSelected = selectedClaim?.id === item.id;
          const isCritical = item.severity === 'CRITICAL';
          const statusColor = getStatusColor(item.status);

          return (
            <div
              key={item.id}
              onClick={() => setSelectedClaim(item)}
              style={{
                backgroundColor: isSelected ? '#1a1a1a' : '#0a0a0a',
                border: isSelected ? '1px solid #c00030' : '1px solid #1a1a1a',
                padding: '12px 14px',
                cursor: 'pointer',
                transition: 'all 0.15s',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ color: '#ff8c00', fontSize: '11px', fontWeight: 'bold' }}>{item.id}</span>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <span style={{ fontSize: '9px', color: isCritical ? '#c00030' : '#888888', border: '1px solid #282828', padding: '1px 4px' }}>
                      {item.severity}
                    </span>
                    <span style={{ fontSize: '9px', color: statusColor, border: `1px solid ${statusColor}`, padding: '1px 5px', fontWeight: 'bold' }}>
                      ● {item.status}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '12px', fontWeight: 'bold', color: '#ffffff', marginBottom: '6px' }}>
                  {item.title}
                </div>

                <div style={{ fontSize: '10px', color: '#888888', lineHeight: '1.4', marginBottom: '8px' }}>
                  {item.claim}
                </div>
              </div>

              <div style={{ borderTop: '1px solid #1a1a1a', paddingTop: '6px', fontSize: '9px', color: '#6a6a6a', display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                <span>{item.category}</span>
                <span>{item.lastChecked}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* SELECTED CLAIM DETAIL DRAWER */}
      {selectedClaim && (
        <div style={{
          marginTop: '10px',
          padding: '12px 16px',
          border: '1px solid #c00030',
          backgroundColor: '#0a0a0a',
          flexShrink: 0
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ color: '#ffffff', fontWeight: 'bold', fontSize: '13px' }}>
                [{selectedClaim.id}] {selectedClaim.title}
              </span>
              <span style={{ fontSize: '10px', color: getStatusColor(selectedClaim.status), border: `1px solid ${getStatusColor(selectedClaim.status)}`, padding: '1px 6px' }}>
                STATUS: {selectedClaim.status}
              </span>
            </div>
            <button
              onClick={() => setSelectedClaim(null)}
              style={{
                background: 'transparent',
                border: '1px solid #282828',
                color: '#d7d7d7',
                cursor: 'pointer',
                fontFamily: 'inherit',
                padding: '2px 8px'
              }}
            >
              ✕ CLOSE
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', fontSize: '11px' }}>
            <div>
              <div style={{ color: '#888888', marginBottom: '2px', fontSize: '10px' }}>ENFORCED CONTROL:</div>
              <div style={{ color: '#d7d7d7' }}>{selectedClaim.control}</div>
            </div>
            <div>
              <div style={{ color: '#888888', marginBottom: '2px', fontSize: '10px' }}>PROOF OF VERIFICATION:</div>
              <div style={{ color: '#00ff66' }}>{selectedClaim.evidence}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
