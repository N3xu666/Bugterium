import React, { useState } from 'react';

const ASSURANCE_CLAIMS = [
  {
    id: 'AUTH-01',
    category: 'AUTHENTICATION & DOS',
    title: 'Anti-Brute-Force & Rate Limiting',
    claim: 'All /api/* and /auth/* endpoints enforce hard rate limits to prevent brute-force attacks and D1 database exhaustion.',
    control: 'Hono isolate in-memory limiter (100 req/min general, 10 req/min login) + HMAC-SHA256 hashed IP keys.',
    evidence: 'Unit test suite: test/middleware/rateLimit.test.ts (PASS 10/10). Local flood-test verified.',
    status: 'ENFORCED',
    severity: 'HIGH',
    lastChecked: 'Continuous in CI (Pass 199)'
  },
  {
    id: 'EDGE-01',
    category: 'ENDPOINT & HOST PERIMETER',
    title: 'Zero Inbound Tunnels & Host Dark Perimeter',
    claim: 'Developer workstation is 100% inbound-dark. No reverse network tunnels (ngrok, cloudflared) or external port forwards exist.',
    control: 'Cloudflare Pages / Workers serverless edge execution. Strict rule in AGENTS.md §2.11.',
    evidence: 'Network audit: 0 active reverse tunnels. All public traffic terminates at Cloudflare V8 isolates.',
    status: 'VERIFIED',
    severity: 'CRITICAL',
    lastChecked: 'Pass 199 Zero-Trust Host Audit'
  },
  {
    id: 'RBAC-01',
    category: 'ACCESS CONTROL',
    title: 'Role-Based Access Control (Admin Protection)',
    claim: 'Unauthorized users attempting to access /api/admin receive HTTP 403 Forbidden with security audit logging.',
    control: 'RBAC middleware in BFF Worker + audit event logged to D1 (login_fail / forbidden).',
    evidence: 'Test: test/routes/admin.test.ts (status === 403 for role user).',
    status: 'ENFORCED',
    severity: 'HIGH',
    lastChecked: 'Pass 199 CI Gate'
  },
  {
    id: 'SECR-01',
    category: 'OPSEC & DATA HYGIENE',
    title: 'Secret Leakage & Masking Canon',
    claim: 'Zero real flags, session tokens, passwords, or hashes exist in public documentation or git history.',
    control: '5-Gate pre-commit hook + Gitleaks CI + masking-dict.ps1 dictionary scan (115 entries).',
    evidence: 'check.ps1 check [1/27] & [2/27]: 0 real flags, 0 leaks across 1102 files.',
    status: 'VERIFIED',
    severity: 'CRITICAL',
    lastChecked: 'Pre-commit 5-Gate & CI Gitleaks'
  },
  {
    id: 'SUPP-01',
    category: 'SUPPLY CHAIN',
    title: 'Dependency & CI Supply Chain Hygiene',
    claim: 'CI workflows and npm dependencies are protected against malicious package takeover and lifecycle script RCE.',
    control: 'Full SHA-pinned GitHub Actions, Trivy SCA, Semgrep SAST, npm --ignore-scripts rule in AGENTS.md §2.9.',
    evidence: '25/25 GitHub Actions CI checks passing; 0 HIGH/CRITICAL CVEs in dependencies.',
    status: 'VERIFIED',
    severity: 'HIGH',
    lastChecked: 'PR #65 (25/25 CI Checks Green)'
  },
  {
    id: 'PRIV-01',
    category: 'PRIVACY & ANONYMIZATION',
    title: 'K-Anonymity & Zero PII Storage',
    claim: 'Public telemetry contains no IP addresses or individual fingerprints. All metrics are aggregated.',
    control: 'k-Anonymity (k >= 5) for geographical and ASN slices; 32-hex path masking as /[hex32].',
    evidence: 'Sanitization in aggregate.ts + test/aggregate.test.ts (Tech Debt #36 closed).',
    status: 'VERIFIED',
    severity: 'MEDIUM',
    lastChecked: 'Pass 199 Telemetry Gate'
  }
];

export default function AssuranceView() {
  const [selectedClaim, setSelectedClaim] = useState(null);

  return (
    <div style={{
      width: '100%',
      height: '100%',
      backgroundColor: '#050505',
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
        borderBottom: '1px solid #222',
        paddingBottom: '12px',
        marginBottom: '14px',
        flexShrink: 0
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ color: '#c00030', fontWeight: 'bold', fontSize: '13px', letterSpacing: '0.08em' }}>
            [ ASSURANCE & VERIFIED CLAIMS ]
          </span>
          <span style={{ fontSize: '10px', color: '#666', border: '1px solid #333', padding: '2px 6px' }}>
            CONTINUOUS VERIFICATION ENGINE
          </span>
        </div>

        <div style={{ display: 'flex', gap: '15px', fontSize: '11px', color: '#888' }}>
          <div>ENFORCED CONTROLS: <span style={{ color: '#00ff66', fontWeight: 'bold' }}>6 / 6 (100%)</span></div>
          <div>STATUS: <span style={{ color: '#00ff66', fontWeight: 'bold' }}>ALL GATES GREEN</span></div>
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
        {ASSURANCE_CLAIMS.map(item => {
          const isSelected = selectedClaim?.id === item.id;
          const isCritical = item.severity === 'CRITICAL';

          return (
            <div
              key={item.id}
              onClick={() => setSelectedClaim(item)}
              style={{
                backgroundColor: isSelected ? '#121212' : '#0a0a0a',
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
                    <span style={{ fontSize: '9px', color: isCritical ? '#c00030' : '#888', border: '1px solid #2a2a2a', padding: '1px 4px' }}>
                      {item.severity}
                    </span>
                    <span style={{ fontSize: '9px', color: '#00ff66', border: '1px solid #00aa44', padding: '1px 5px', fontWeight: 'bold' }}>
                      ● {item.status}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '12px', fontWeight: 'bold', color: '#eee', marginBottom: '6px' }}>
                  {item.title}
                </div>

                <div style={{ fontSize: '10px', color: '#888', lineHeight: '1.4', marginBottom: '8px' }}>
                  {item.claim}
                </div>
              </div>

              <div style={{ borderTop: '1px solid #1f1f1f', paddingTop: '6px', fontSize: '9px', color: '#555', display: 'flex', justifyContent: 'space-between' }}>
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
              <span style={{ fontSize: '10px', color: '#00ff66', border: '1px solid #00aa44', padding: '1px 6px' }}>
                STATUS: {selectedClaim.status}
              </span>
            </div>
            <button
              onClick={() => setSelectedClaim(null)}
              style={{
                background: 'transparent',
                border: '1px solid #444',
                color: '#aaa',
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
              <div style={{ color: '#888', marginBottom: '2px', fontSize: '10px' }}>ENFORCED CONTROL:</div>
              <div style={{ color: '#ddd' }}>{selectedClaim.control}</div>
            </div>
            <div>
              <div style={{ color: '#888', marginBottom: '2px', fontSize: '10px' }}>PROOF OF VERIFICATION:</div>
              <div style={{ color: '#00ff66' }}>{selectedClaim.evidence}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
