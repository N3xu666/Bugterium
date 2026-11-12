import React from 'react';

export default function LensesHub({ onSelectLens, metrics }) {
  const lenses = [
    {
      id: 'neural-port',
      tag: 'LENS 01 // KNOWLEDGE BRAIN',
      title: 'NEURAL PORT',
      desc: 'Interactive 3D knowledge taxonomy, machine writeups, tools, CVEs, and MITRE adversary mapping.',
      icon: (
        <svg width="88" height="88" viewBox="0 0 64 64" fill="none">
          {/* Нейронные связи и волокна графа знаний */}
          <g stroke="#c00030" strokeWidth="1" strokeOpacity="0.45">
            <line x1="38" y1="26" x2="48" y2="18" />
            <line x1="38" y1="26" x2="43" y2="12" />
            <line x1="48" y1="18" x2="43" y2="12" />
            <line x1="48" y1="18" x2="55" y2="22" />
            <line x1="55" y1="22" x2="58" y2="16" />
            
            <line x1="37" y1="38" x2="47" y2="44" />
            <line x1="47" y1="44" x2="43" y2="52" />
            <line x1="47" y1="44" x2="54" y2="50" />
            <line x1="43" y1="52" x2="54" y2="50" />

            <line x1="27" y1="39" x2="20" y2="48" />
            <line x1="20" y1="48" x2="28" y2="54" />
            <line x1="20" y1="48" x2="13" y2="52" />
            <line x1="13" y1="52" x2="8" y2="45" />

            <line x1="24" y1="30" x2="14" y2="24" />
            <line x1="14" y1="24" x2="18" y2="15" />
            <line x1="14" y1="24" x2="8" y2="30" />
            <line x1="18" y1="15" x2="26" y2="13" />
            <line x1="26" y1="13" x2="33" y2="18" />
            <line x1="33" y1="18" x2="38" y2="26" />

            <line x1="43" y1="12" x2="26" y2="13" strokeDasharray="2 2" strokeOpacity="0.25" />
            <line x1="43" y1="52" x2="28" y2="54" strokeDasharray="2 2" strokeOpacity="0.25" />
          </g>

          {/* Органическое метаболлическое тело клетки */}
          <path d="M 32 23
                   C 36 23, 38 24, 41 25
                   C 44 26, 45 28, 44 31
                   C 43 33, 40 34, 40 36
                   C 40 38, 42 41, 39 43
                   C 36 45, 34 42, 32 41
                   C 30 40, 28 43, 25 42
                   C 22 41, 24 37, 25 35
                   C 26 33, 22 32, 21 29
                   C 20 26, 23 25, 26 26
                   C 28 27, 29 23, 32 23 Z"
                fill="#c00030" />
          
          {/* Слитые капли метаболла для органического объема */}
          <circle cx="32" cy="31" r="6" fill="#c00030" />
          <circle cx="38" cy="26" r="4.2" fill="#c00030" />
          <circle cx="37" cy="38" r="3.8" fill="#c00030" />
          <circle cx="24" cy="30" r="4.0" fill="#c00030" />
          <circle cx="27" cy="39" r="3.5" fill="#c00030" />

          {/* Кластерные периферийные узлы графа */}
          <circle cx="48" cy="18" r="2.4" fill="#c00030" />
          <circle cx="43" cy="12" r="1.8" fill="#c00030" />
          <circle cx="55" cy="22" r="1.6" fill="#c00030" />
          <circle cx="58" cy="16" r="1.2" fill="#c00030" />

          <circle cx="47" cy="44" r="2.2" fill="#c00030" />
          <circle cx="43" cy="52" r="1.7" fill="#c00030" />
          <circle cx="54" cy="50" r="1.4" fill="#c00030" />

          <circle cx="20" cy="48" r="2.3" fill="#c00030" />
          <circle cx="28" cy="54" r="1.6" fill="#c00030" />
          <circle cx="13" cy="52" r="1.3" fill="#c00030" />
          <circle cx="8" cy="45" r="1.1" fill="#c00030" />

          <circle cx="14" cy="24" r="2.4" fill="#c00030" />
          <circle cx="18" cy="15" r="1.8" fill="#c00030" />
          <circle cx="8" cy="30" r="1.5" fill="#c00030" />
          <circle cx="26" cy="13" r="1.6" fill="#c00030" />
          <circle cx="33" cy="18" r="1.8" fill="#c00030" />
        </svg>
      )
    },
    {
      id: 'globe',
      tag: 'LENS 02 // EDGE TELEMETRY',
      title: 'GLOBE',
      desc: 'Real-time isolated edge threat telemetry, ingress attack vector arcs, and WAF defense rings.',
      icon: (
        <svg width="88" height="88" viewBox="0 0 64 64" fill="none">
          {/* Внешний контур сферы глобуса */}
          <circle cx="32" cy="32" r="20" stroke="#c00030" strokeWidth="1.8" />

          {/* Горизонтальный экватор */}
          <ellipse cx="32" cy="32" rx="20" ry="6" stroke="#c00030" strokeWidth="1.4" />

          {/* Параллели широты (северная и южная) */}
          <ellipse cx="32" cy="22" rx="17.3" ry="4.5" stroke="#c00030" strokeWidth="1.1" />
          <ellipse cx="32" cy="42" rx="17.3" ry="4.5" stroke="#c00030" strokeWidth="1.1" />

          {/* Меридианы долготы */}
          <ellipse cx="32" cy="32" rx="7" ry="20" stroke="#c00030" strokeWidth="1.1" />
          <ellipse cx="32" cy="32" rx="14" ry="20" stroke="#c00030" strokeWidth="1.1" />

          {/* Центральный меридиан / ось (строго от полюса до полюса, не выступает) */}
          <line x1="32" y1="12" x2="32" y2="52" stroke="#c00030" strokeWidth="1.2" />
        </svg>
      )
    },
    {
      id: 'attack-matrix',
      tag: 'LENS 03 // ADVERSARY TACTICS',
      title: 'ATT&CK MATRIX',
      desc: 'Enterprise MITRE ATT&CK coverage tracking real-time probed vs verified covered defense techniques.',
      icon: (
        <svg width="88" height="88" viewBox="0 0 32 32" fill="none">
          <rect x="5" y="6" width="9" height="8" stroke="#c00030" strokeWidth="1.2" fill="rgba(192,0,48,0.25)" />
          <rect x="18" y="6" width="9" height="8" stroke="#c00030" strokeWidth="1" strokeOpacity="0.35" fill="rgba(192,0,48,0.05)" />
          <rect x="5" y="18" width="9" height="8" stroke="#c00030" strokeWidth="1" strokeOpacity="0.35" fill="rgba(192,0,48,0.05)" />
          <rect x="18" y="18" width="9" height="8" stroke="#c00030" strokeWidth="1.2" fill="rgba(192,0,48,0.25)" />
        </svg>
      )
    },
    {
      id: 'assurance',
      tag: 'LENS 04 // DEFENSIVE POSTURE',
      title: 'ASSURANCE',
      desc: 'Continuous verification of edge security controls, Zero Trust policies, and telemetry immutability.',
      icon: (
        <svg width="88" height="88" viewBox="0 0 32 32" fill="none">
          <path d="M16 4 L26 8 V16 C26 22 16 28 16 28 C16 28 6 22 6 16 V8 Z" stroke="#c00030" strokeWidth="1.2" fill="rgba(192,0,48,0.08)" />
          <path d="M11 16 L14 19 L21 12" stroke="#c00030" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )
    }
  ];

  return (
    <div style={{
      width: '100%',
      height: '100%',
      display: 'grid',
      gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
      gridTemplateRows: 'repeat(2, minmax(0, 1fr))',
      gap: '12px',
      padding: '14px',
      boxSizing: 'border-box',
      background: '#000000'
    }}>
      {lenses.map((lens) => (
        <div
          key={lens.id}
          onClick={() => onSelectLens(lens.id)}
          style={{
            position: 'relative',
            background: '#0a0a0a',
            border: '1px solid #1a1a1a',
            padding: '24px 22px 18px 22px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            cursor: 'pointer',
            transition: 'border-color 0.18s ease, background-color 0.18s ease, transform 0.18s ease',
            fontFamily: "'JetBrains Mono', ui-monospace, monospace",
            overflow: 'hidden'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = '#c00030';
            e.currentTarget.style.backgroundColor = 'rgba(192, 0, 48, 0.05)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = '#1a1a1a';
            e.currentTarget.style.backgroundColor = '#0a0a0a';
          }}
        >
          {/* Top header */}
          <div>
            <div style={{ marginBottom: '22px' }}>
              <span style={{ fontSize: '9px', color: '#6a6a6a', letterSpacing: '0.12em', fontWeight: 'bold' }}>
                {lens.tag}
              </span>
            </div>
            
            <h3 style={{ 
              fontSize: '15px', 
              color: '#ffffff', 
              letterSpacing: '0.06em', 
              margin: '0 0 8px 0',
              fontWeight: '600'
            }}>
              {lens.title}
            </h3>
            
            <p style={{ 
              fontSize: '11px', 
              color: '#888888', 
              lineHeight: '1.45', 
              margin: 0,
              maxWidth: '92%'
            }}>
              {lens.desc}
            </p>
          </div>

          {/* Central large icon */}
          <div style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '16px 0 8px 0'
          }}>
            {lens.icon}
          </div>

          {/* Bottom action */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderTop: '1px solid #161616',
            paddingTop: '8px',
            fontSize: '10px',
            color: '#c00030',
            letterSpacing: '0.08em',
            fontWeight: 'bold',
            marginTop: '12px'
          }}>
            <span>ENGAGE LENS</span>
            <span>[ ↗ ]</span>
          </div>
        </div>
      ))}
    </div>
  );
}
