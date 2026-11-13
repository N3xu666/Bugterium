import React, { useState } from 'react';

const TACTICS_DATA = [
  {
    id: 'TA0043',
    name: 'RECONNAISSANCE',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', status: 'probed', desc: 'Pre-attack automated port & path scanning against edge endpoints.', ref: '/reference/applications/web/reconnaissance' },
      { id: 'T1592', name: 'Gather Victim Host Info', status: 'researched', desc: 'OSINT reconnaissance of victim server architecture.', ref: '/reference/osint/methodology' },
      { id: 'T1590', name: 'Gather Victim Network Info', status: 'researched', desc: 'DNS, ASN, and network topology mapping.', ref: '/reference/networks/protocols/dns' }
    ]
  },
  {
    id: 'TA0001',
    name: 'INITIAL ACCESS',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing App', status: 'probed', desc: 'Targeting known vulnerabilities in web applications (CVE-2018-9276, WordPress probes).', ref: '/reference/applications/web/vulnerabilities/command-injection' },
      { id: 'T1078', name: 'Valid Accounts', status: 'researched', desc: 'Default or compromised credentials usage (Tomcat, Netmon, ServMon).', ref: '/reference/information-security/access-control/iam' },
      { id: 'T1133', name: 'External Remote Services', status: 'researched', desc: 'SSH, WinRM, or VPN access with harvested credentials.', ref: '/reference/infrastructure/windows/fundamentals' }
    ]
  },
  {
    id: 'TA0002',
    name: 'EXECUTION',
    techniques: [
      { id: 'T1059', name: 'Command & Script Interpreter', status: 'researched', desc: 'Bash, PowerShell, and cmd.exe payload execution.', ref: '/reference/infrastructure/windows/fundamentals' },
      { id: 'T1203', name: 'Exploitation for Client Execution', status: 'researched', desc: 'Malicious CHM / macro execution for foothold.', ref: '/reference/applications/web/vulnerabilities/file-upload' }
    ]
  },
  {
    id: 'TA0003',
    name: 'PERSISTENCE',
    techniques: [
      { id: 'T1053', name: 'Scheduled Task / Job', status: 'researched', desc: 'Cron jobs and Windows scheduled tasks (job.bat privesc).', ref: '/reference/infrastructure/windows/persistence' },
      { id: 'T1505', name: 'Server Software Component', status: 'researched', desc: 'Web shell deployment into Tomcat or IIS directories.', ref: '/reference/applications/web/vulnerabilities/file-upload' }
    ]
  },
  {
    id: 'TA0004',
    name: 'PRIVILEGE ESCALATION',
    techniques: [
      { id: 'T1068', name: 'Exploitation for PrivEsc', status: 'researched', desc: 'Kernel exploits and local service vulnerabilities (NSClient++).', ref: '/reference/infrastructure/windows/privilege-escalation' },
      { id: 'T1548', name: 'Abuse Elevation Control', status: 'researched', desc: 'Sudo misconfiguration and UAC bypass techniques.', ref: '/reference/infrastructure/windows/privilege-escalation' }
    ]
  },
  {
    id: 'TA0005',
    name: 'DEFENSE EVASION',
    techniques: [
      { id: 'T1070', name: 'Indicator Removal on Host', status: 'researched', desc: 'Artifact cleanup and log purging after intrusion.', ref: '/reference/anonymity-privacy-opsec/opsec' },
      { id: 'T1027', name: 'Obfuscated Files or Info', status: 'researched', desc: 'Base64 encoding and payload obfuscation.', ref: '/reference/applications/web/vulnerabilities/xss' }
    ]
  },
  {
    id: 'TA0006',
    name: 'CREDENTIAL ACCESS',
    techniques: [
      { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', status: 'researched', desc: 'Kerberoasting and AS-REP Roasting in Active Directory.', ref: '/reference/infrastructure/active-directory/enumeration' },
      { id: 'T1003', name: 'OS Credential Dumping', status: 'researched', desc: 'DCSync, LSASS dumping, and SAM registry hive extraction.', ref: '/reference/infrastructure/active-directory/privilege-escalation' },
      { id: 'T1552', name: 'Unsecured Credentials', status: 'probed', desc: 'Searching for .env, .aws/credentials, and web.config leaks.', ref: '/reference/applications/web/vulnerabilities/information-disclosure' },
      { id: 'T1110', name: 'Brute Force', status: 'probed', desc: 'Automated password spraying and credential stuffing.', ref: '/reference/information-security/access-control/authentication' }
    ]
  },
  {
    id: 'TA0007',
    name: 'DISCOVERY',
    techniques: [
      { id: 'T1046', name: 'Network Service Discovery', status: 'probed', desc: 'Port enumeration with Nmap, masscan, and edge probes.', ref: '/reference/networks/protocols/tcp-udp' },
      { id: 'T1082', name: 'System Information Discovery', status: 'researched', desc: 'Host enumeration (systeminfo, uname -a).', ref: '/reference/infrastructure/windows/fundamentals' },
      { id: 'T1087', name: 'Account Discovery', status: 'researched', desc: 'Active Directory and local user enumeration.', ref: '/reference/infrastructure/active-directory/enumeration' }
    ]
  },
  {
    id: 'TA0008',
    name: 'LATERAL MOVEMENT',
    techniques: [
      { id: 'T1021', name: 'Remote Services', status: 'researched', desc: 'Pass-the-Hash over SMB, WinRM, and WMI execution.', ref: '/reference/infrastructure/active-directory/lateral-movement' },
      { id: 'T1550', name: 'Use Alternate Authentication Material', status: 'researched', desc: 'Pass-the-Ticket, Pass-the-Hash with NTLM.', ref: '/reference/infrastructure/active-directory/authentication-attacks' }
    ]
  },
  {
    id: 'TA0011',
    name: 'COMMAND & CONTROL',
    techniques: [
      { id: 'T1071', name: 'Application Layer Protocol', status: 'researched', desc: 'Reverse shells over HTTP/HTTPS, DNS tunneling.', ref: '/reference/networks/protocols/http' },
      { id: 'T1572', name: 'Protocol Tunneling', status: 'researched', desc: 'Chisel, SSH dynamic port forwarding, and ligolo-ng.', ref: '/reference/networks/protocols/tcp-udp' }
    ]
  }
];

const TECHNIQUE_TELEMETRY_MAP = {
  T1595: {
    sourceLabel: 'hex32_probe + phpinfo + ua_scanner',
    countFromSnapshot: (snap) => {
      const families = snap?.probes?.families || [];
      const uas = snap?.ua_families || [];
      const hex = families.find((f) => f.family === 'hex32_probe')?.count || 0;
      const php = families.find((f) => f.family === 'phpinfo')?.count || 0;
      const scan = uas.find((u) => u.family === 'scanner')?.count || 0;
      const auto = uas.find((u) => u.family === 'automation')?.count || 0;
      return hex + php + scan + auto;
    }
  },
  T1190: {
    sourceLabel: 'wordpress + api_probe + db_probe',
    countFromSnapshot: (snap) => {
      const families = snap?.probes?.families || [];
      return families
        .filter((f) => f.family === 'wordpress' || f.family === 'api_probe' || f.family === 'db_probe')
        .reduce((acc, f) => acc + (f.count || 0), 0);
    }
  },
  T1505: {
    sourceLabel: 'probes.families: shell',
    countFromSnapshot: (snap) => {
      const families = snap?.probes?.families || [];
      return families.find((f) => f.family === 'shell')?.count || 0;
    }
  },
  T1552: {
    sourceLabel: 'env_file + git + aws_creds',
    countFromSnapshot: (snap) => {
      const families = snap?.probes?.families || [];
      return families
        .filter((f) => f.family === 'env_file' || f.family === 'git' || f.family === 'aws_creds')
        .reduce((acc, f) => acc + (f.count || 0), 0);
    }
  },
  T1110: {
    sourceLabel: 'auth.totals (login_fail + forbidden)',
    countFromSnapshot: (snap) => {
      if (!snap?.auth?.totals) return 0;
      return (snap.auth.totals.login_fail || 0) + (snap.auth.totals.forbidden || 0);
    }
  },
  T1046: {
    sourceLabel: 'ua_families (scanner + crawler)',
    countFromSnapshot: (snap) => {
      const uas = snap?.ua_families || [];
      return uas
        .filter((u) => u.family === 'scanner' || u.family === 'crawler')
        .reduce((acc, u) => acc + (u.count || 0), 0);
    }
  }
};

export default function AttackMatrix({ snapshot = null }) {
  const [selectedTech, setSelectedTech] = useState(null);
  const [filter, setFilter] = useState('all');

  const hasTelemetry = Boolean(snapshot && (snapshot.probes || snapshot.ua_families || snapshot.auth));

  const enrichedTactics = TACTICS_DATA.map((tactic) => ({
    ...tactic,
    techniques: tactic.techniques.map((tech) => {
      const binding = TECHNIQUE_TELEMETRY_MAP[tech.id];
      const liveHits = hasTelemetry && binding ? binding.countFromSnapshot(snapshot) : null;
      const status = hasTelemetry && binding
        ? (liveHits > 0 ? 'probed' : 'researched')
        : tech.status;
      return {
        ...tech,
        status,
        liveHits,
        sourceLabel: binding ? binding.sourceLabel : null
      };
    })
  }));

  const totalTechniques = enrichedTactics.reduce((acc, t) => acc + t.techniques.length, 0);
  const probedCount = enrichedTactics.reduce(
    (acc, t) => acc + t.techniques.filter((tech) => tech.status === 'probed').length,
    0
  );

  const filteredTactics = enrichedTactics.map(tactic => ({
    ...tactic,
    techniques: tactic.techniques.filter(tech => {
      if (filter === 'researched') return tech.status === 'researched';
      if (filter === 'probed') return tech.status === 'probed';
      return true;
    })
  }));

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
      {/* HEADER BAR */}
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
          <span style={{ color: '#00ff66', fontWeight: 'bold', fontSize: '13px', letterSpacing: '0.08em' }}>
            [ ATT&CK COVERAGE MATRIX ]
          </span>
          <span style={{ fontSize: '10px', color: '#6a6a6a', border: '1px solid #282828', padding: '2px 6px' }}>
            {probedCount} PROBED (24H) // {totalTechniques} MAPPED ({TACTICS_DATA.length} TACTICS)
          </span>
        </div>

        {/* FILTERS */}
        <div style={{ display: 'flex', gap: '8px', fontSize: '11px' }}>
          <button
            onClick={() => setFilter('all')}
            style={{
              background: filter === 'all' ? '#1a1a1a' : 'transparent',
              color: filter === 'all' ? '#ffffff' : '#6a6a6a',
              border: '1px solid #282828',
              padding: '3px 8px',
              cursor: 'pointer',
              fontFamily: 'inherit'
            }}
          >
            ALL ({totalTechniques})
          </button>
          <button
            onClick={() => setFilter('researched')}
            style={{
              background: filter === 'researched' ? 'rgba(0, 255, 102, 0.12)' : 'transparent',
              color: filter === 'researched' ? '#00ff66' : '#6a6a6a',
              border: '1px solid #00ff66',
              padding: '3px 8px',
              cursor: 'pointer',
              fontFamily: 'inherit'
            }}
          >
            RESEARCHED ({totalTechniques - probedCount})
          </button>
          <button
            onClick={() => setFilter('probed')}
            style={{
              background: filter === 'probed' ? 'rgba(192, 0, 48, 0.12)' : 'transparent',
              color: filter === 'probed' ? '#c00030' : '#6a6a6a',
              border: '1px solid #c00030',
              padding: '3px 8px',
              cursor: 'pointer',
              fontFamily: 'inherit'
            }}
          >
            PROBED LIVE ({probedCount})
          </button>
        </div>
      </div>

      {/* MATRIX COLUMNS GRID */}
      <div style={{
        flex: 1,
        display: 'flex',
        gap: '8px',
        overflowX: 'auto',
        overflowY: 'auto',
        minHeight: 0,
        paddingBottom: '10px'
      }}>
        {filteredTactics.map(tactic => (
          <div
            key={tactic.id}
            style={{
              flex: '0 0 180px',
              display: 'flex',
              flexDirection: 'column',
              backgroundColor: '#0a0a0a',
              border: '1px solid #1a1a1a',
              overflow: 'hidden'
            }}
          >
            {/* TACTIC HEADER */}
            <div style={{
              padding: '8px',
              borderBottom: '1px solid #1a1a1a',
              backgroundColor: '#0a0a0a',
              fontSize: '11px',
              fontWeight: 'bold',
              color: '#ff8c00',
              letterSpacing: '0.04em'
            }}>
              <div>{tactic.name}</div>
              <div style={{ fontSize: '9px', color: '#6a6a6a', fontWeight: 'normal', marginTop: '2px' }}>{tactic.id}</div>
            </div>

            {/* TECHNIQUES LIST */}
            <div style={{ padding: '6px', display: 'flex', flexDirection: 'column', gap: '6px', flex: 1, overflowY: 'auto' }}>
              {tactic.techniques.map(tech => {
                const isSelected = selectedTech?.id === tech.id;
                const isProbed = tech.status === 'probed';
                const color = isProbed ? '#c00030' : '#00ff66';
                const bg = isSelected ? '#1a1a1a' : (isProbed ? 'rgba(192, 0, 48, 0.10)' : 'rgba(0, 255, 102, 0.05)');
                const border = isSelected ? '1px solid #c00030' : (isProbed ? '1px solid rgba(192, 0, 48, 0.45)' : '1px solid rgba(0, 255, 102, 0.25)');

                return (
                  <div
                    key={tech.id}
                    onClick={() => setSelectedTech(tech)}
                    style={{
                      padding: '6px 8px',
                      backgroundColor: bg,
                      border: border,
                      cursor: 'pointer',
                      transition: 'all 0.15s'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '9px', marginBottom: '2px' }}>
                      <span style={{ color: color, fontWeight: 'bold' }}>{tech.id}</span>
                      <span style={{ fontSize: '8px', color: isProbed ? '#c00030' : '#00ff66', fontWeight: isProbed ? 'bold' : 'normal' }}>
                        {isProbed
                          ? (tech.liveHits !== null ? `PROBED (${tech.liveHits})` : 'PROBED')
                          : 'COVERED'}
                      </span>
                    </div>
                    <div style={{ fontSize: '10px', color: '#ffffff', lineHeight: '1.2' }}>{tech.name}</div>
                  </div>
                );
              })}
              {tactic.techniques.length === 0 && (
                <div style={{ fontSize: '10px', color: '#6a6a6a', fontStyle: 'italic', padding: '10px 4px', textAlign: 'center' }}>
                  No matching techniques
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* SELECTED TECHNIQUE DETAILS DRAWER */}
      {selectedTech && (
        <div style={{
          marginTop: '10px',
          padding: '12px 16px',
          border: '1px solid #282828',
          backgroundColor: '#0a0a0a',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '12px',
          flexShrink: 0
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px', flexWrap: 'wrap' }}>
              <span style={{ color: selectedTech.status === 'probed' ? '#c00030' : '#00ff66', fontWeight: 'bold', fontSize: '13px' }}>
                [{selectedTech.id}] {selectedTech.name}
              </span>
              <span style={{ fontSize: '10px', color: '#d7d7d7', border: '1px solid #282828', padding: '1px 5px' }}>
                STATUS: {selectedTech.status === 'probed' ? 'OBSERVED IN EDGE TELEMETRY' : 'RESEARCHED IN BUGTERIUM CANON'}
              </span>
              {selectedTech.sourceLabel && (
                <span style={{ fontSize: '10px', color: '#ff8c00', border: '1px solid #282828', padding: '1px 5px' }}>
                  24H HITS: {selectedTech.liveHits ?? 0} ({selectedTech.sourceLabel})
                </span>
              )}
            </div>
            <div style={{ fontSize: '11px', color: '#888888' }}>
              {selectedTech.desc}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexShrink: 0 }}>
            {selectedTech.ref && (
              <a
                href={selectedTech.ref}
                target="_blank"
                rel="noreferrer"
                style={{
                  color: '#c00030',
                  textDecoration: 'none',
                  fontSize: '11px',
                  border: '1px solid #c00030',
                  padding: '4px 8px',
                  letterSpacing: '0.04em'
                }}
              >
                OPEN REFERENCE DOC ↗
              </a>
            )}
            <button
              onClick={() => setSelectedTech(null)}
              style={{
                background: 'transparent',
                border: '1px solid #282828',
                color: '#d7d7d7',
                cursor: 'pointer',
                fontFamily: 'inherit',
                padding: '4px 8px'
              }}
            >
              ✕ CLOSE
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
