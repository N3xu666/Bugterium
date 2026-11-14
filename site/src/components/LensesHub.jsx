import React, { useState, useEffect, useRef } from 'react';

const NEURAL_NODES = [
  // 0: Central nucleus
  { x: 32, y: 32, r: 3.8, dx: -1.5, dy: 1.0, ax: 1.2, ay: 1.0, fx: 2.1, fy: 1.7, ph: 0.0 },
  // 1..5: Inner synaptic ring
  { x: 33, y: 18, r: 2.0, dx: -3.5, dy: 2.5, ax: 1.8, ay: 1.4, fx: 2.6, fy: 2.0, ph: 0.7 },
  { x: 38, y: 26, r: 2.0, dx: 2.5, dy: -2.0, ax: 1.6, ay: 1.7, fx: 2.3, fy: 2.5, ph: 1.4 },
  { x: 37, y: 38, r: 2.0, dx: -2.0, dy: 2.5, ax: 1.7, ay: 1.5, fx: 2.8, fy: 1.9, ph: 2.1 },
  { x: 27, y: 39, r: 2.0, dx: 3.0, dy: -2.5, ax: 1.5, ay: 1.8, fx: 2.2, fy: 2.4, ph: 2.9 },
  { x: 24, y: 30, r: 2.0, dx: -2.5, dy: -3.0, ax: 1.8, ay: 1.4, fx: 2.5, fy: 2.1, ph: 3.6 },
  // 6..9: Top-right cluster
  { x: 48, y: 18, r: 2.3, dx: -3.0, dy: 4.5, ax: 2.0, ay: 1.9, fx: 2.4, fy: 1.8, ph: 0.4 },
  { x: 43, y: 12, r: 1.8, dx: 3.5, dy: -1.5, ax: 1.7, ay: 1.5, fx: 2.9, fy: 2.2, ph: 1.1 },
  { x: 55, y: 22, r: 1.6, dx: -4.0, dy: -4.0, ax: 2.1, ay: 1.8, fx: 2.0, fy: 2.7, ph: 1.9 },
  { x: 58, y: 16, r: 1.2, dx: -5.5, dy: 5.5, ax: 1.8, ay: 2.1, fx: 2.7, fy: 2.3, ph: 2.5 },
  // 10..12: Bottom-right cluster
  { x: 47, y: 44, r: 2.2, dx: 3.0, dy: -4.5, ax: 1.9, ay: 1.7, fx: 2.3, fy: 2.6, ph: 3.2 },
  { x: 43, y: 52, r: 1.7, dx: -4.5, dy: -2.5, ax: 1.6, ay: 1.9, fx: 2.8, fy: 2.0, ph: 4.0 },
  { x: 54, y: 50, r: 1.4, dx: -3.5, dy: -5.0, ax: 2.0, ay: 1.6, fx: 2.1, fy: 2.4, ph: 4.7 },
  // 13..16: Bottom-left cluster
  { x: 20, y: 48, r: 2.3, dx: 4.0, dy: 2.0, ax: 1.9, ay: 1.8, fx: 2.5, fy: 1.9, ph: 5.3 },
  { x: 28, y: 54, r: 1.6, dx: -5.0, dy: -3.0, ax: 1.7, ay: 1.5, fx: 2.2, fy: 2.8, ph: 0.9 },
  { x: 13, y: 52, r: 1.3, dx: 4.5, dy: -4.0, ax: 2.1, ay: 1.7, fx: 2.6, fy: 2.1, ph: 1.7 },
  { x: 8, y: 45, r: 1.2, dx: 4.0, dy: -6.0, ax: 1.6, ay: 2.0, fx: 2.4, fy: 2.5, ph: 2.8 },
  // 17..20: Top-left cluster
  { x: 14, y: 24, r: 2.3, dx: 2.5, dy: 4.5, ax: 1.8, ay: 1.9, fx: 2.7, fy: 2.2, ph: 3.9 },
  { x: 18, y: 15, r: 1.8, dx: -3.0, dy: 3.5, ax: 1.7, ay: 1.6, fx: 2.1, fy: 2.6, ph: 4.4 },
  { x: 8, y: 30, r: 1.5, dx: 4.0, dy: -5.0, ax: 2.0, ay: 1.7, fx: 2.5, fy: 1.8, ph: 5.1 },
  { x: 26, y: 13, r: 1.6, dx: -3.5, dy: 3.0, ax: 1.6, ay: 1.8, fx: 2.9, fy: 2.3, ph: 5.8 }
];

const NEURAL_EDGES = [
  // Central radial spokes
  [0, 1], [0, 2], [0, 3], [0, 4], [0, 5],
  // Inner synaptic pentagon
  [1, 2], [2, 3], [3, 4], [4, 5], [5, 1],
  // Top-right branch
  [2, 6], [2, 7], [6, 7], [6, 8], [8, 9],
  // Bottom-right branch
  [3, 10], [10, 11], [10, 12], [11, 12],
  // Bottom-left branch
  [4, 13], [13, 14], [13, 15], [15, 16],
  // Top-left branch
  [5, 17], [17, 18], [17, 19], [18, 20], [20, 1],
  // Cross-hemisphere bridges
  [7, 20], [11, 14]
];

function NeuralPortIcon({ isHovered }) {
  const [frame, setFrame] = useState({ t: 0, morph: 0 });
  const stateRef = useRef({ t: 0, morph: 0, lastTs: 0 });

  useEffect(() => {
    let rafId = 0;
    stateRef.current.lastTs = 0;

    const tick = (ts) => {
      const s = stateRef.current;
      const dt = s.lastTs ? Math.min(0.05, (ts - s.lastTs) / 1000) : 0.016;
      s.lastTs = ts;

      if (isHovered) {
        s.morph = Math.min(1, s.morph + dt * 4.5);
        s.t += dt;
      } else {
        s.morph = Math.max(0, s.morph - dt * 5.0);
        if (s.morph > 0) {
          s.t += dt * s.morph;
        } else {
          s.t = 0;
        }
      }

      setFrame({ t: s.t, morph: s.morph });

      if (isHovered || s.morph > 0.001) {
        rafId = requestAnimationFrame(tick);
      } else {
        stateRef.current.t = 0;
        stateRef.current.morph = 0;
        setFrame({ t: 0, morph: 0 });
      }
    };

    if (isHovered || stateRef.current.morph > 0.001) {
      rafId = requestAnimationFrame(tick);
    }

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, [isHovered]);

  const { t, morph } = frame;
  const pts = NEURAL_NODES.map((n, idx) => {
    const waveX = Math.sin(t * n.fx + n.ph) * n.ax;
    const waveY = Math.cos(t * n.fy + n.ph * 1.15) * n.ay;
    const pulse = idx === 0 ? Math.sin(t * 3.2) * 0.45 : Math.sin(t * 2.6 + n.ph) * 0.25;
    return {
      x: n.x + (n.dx + waveX) * morph,
      y: n.y + (n.dy + waveY) * morph,
      r: n.r + pulse * morph
    };
  });

  return (
    <svg width="116" height="116" viewBox="0 0 64 64" fill="none">
      {/* Solid neural connections without dashes or opacity */}
      <g stroke="currentColor" strokeWidth="0.65">
        {NEURAL_EDGES.map(([a, b], i) => (
          <line
            key={i}
            x1={pts[a].x}
            y1={pts[a].y}
            x2={pts[b].x}
            y2={pts[b].y}
          />
        ))}
      </g>

      {/* Nodes: pure contours at rest, solid filled in active state */}
      {pts.map((pt, i) => (
        <circle
          key={i}
          cx={pt.x}
          cy={pt.y}
          r={pt.r}
          fill={isHovered ? 'currentColor' : 'var(--bg)'}
          stroke="currentColor"
          strokeWidth="0.8"
        />
      ))}
    </svg>
  );
}

function GlobeIcon({ isHovered }) {
  const [angle, setAngle] = useState(0);
  const animRef = useRef({ angle: 0, lastTs: 0 });

  useEffect(() => {
    if (!isHovered) {
      animRef.current.lastTs = 0;
      return undefined;
    }

    let rafId = 0;
    animRef.current.lastTs = 0;

    const tick = (ts) => {
      const a = animRef.current;
      const dt = a.lastTs ? Math.min(0.05, (ts - a.lastTs) / 1000) : 0.016;
      a.lastTs = ts;
      a.angle = (a.angle + dt * 1.15) % (Math.PI * 2);
      setAngle(a.angle);
      rafId = requestAnimationFrame(tick);
    };

    rafId = requestAnimationFrame(tick);
    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, [isHovered]);

  if (!isHovered) {
    return (
      <svg width="116" height="116" viewBox="0 0 64 64" fill="none">
        {/* Outer globe sphere contour */}
        <circle cx="32" cy="32" r="20" stroke="currentColor" strokeWidth="0.85" />

        {/* Horizontal equator */}
        <ellipse cx="32" cy="32" rx="20" ry="6" stroke="currentColor" strokeWidth="0.7" />

        {/* Latitude parallels (north and south) */}
        <ellipse cx="32" cy="22" rx="17.3" ry="4.5" stroke="currentColor" strokeWidth="0.6" />
        <ellipse cx="32" cy="42" rx="17.3" ry="4.5" stroke="currentColor" strokeWidth="0.6" />

        {/* Longitude meridians */}
        <ellipse cx="32" cy="32" rx="7" ry="20" stroke="currentColor" strokeWidth="0.6" />
        <ellipse cx="32" cy="32" rx="14" ry="20" stroke="currentColor" strokeWidth="0.6" />

        {/* Central meridian axis (strictly pole to pole) */}
        <line x1="32" y1="12" x2="32" y2="52" stroke="currentColor" strokeWidth="0.65" />
      </svg>
    );
  }

  const meridianCount = 12;
  const frontMeridians = [];
  for (let k = 0; k < meridianCount; k += 1) {
    const phi = k * ((Math.PI * 2) / meridianCount) + angle;
    if (Math.cos(phi) >= 0) {
      const xOffset = 20 * Math.sin(phi);
      const rx = Math.abs(xOffset);
      const sweep = xOffset >= 0 ? 1 : 0;
      frontMeridians.push({ key: k, rx, sweep });
    }
  }

  return (
    <svg width="116" height="116" viewBox="0 0 64 64" fill="none">
      <defs>
        <clipPath id="bugterium-globe-clip">
          <circle cx="32" cy="32" r="19.3" />
        </clipPath>
      </defs>

      {/* Filled crimson sphere */}
      <circle cx="32" cy="32" r="20" fill="currentColor" stroke="currentColor" strokeWidth="0.85" />

      {/* Negative-space cutouts clipped cleanly inside the sphere */}
      <g clipPath="url(#bugterium-globe-clip)" fill="none" stroke="var(--bg)">
        <ellipse cx="32" cy="32" rx="20" ry="6" strokeWidth="0.7" />
        <ellipse cx="32" cy="22" rx="17.3" ry="4.5" strokeWidth="0.6" />
        <ellipse cx="32" cy="42" rx="17.3" ry="4.5" strokeWidth="0.6" />

        {frontMeridians.map((m) => (
          m.rx < 0.2 ? (
            <line key={m.key} x1="32" y1="12" x2="32" y2="52" strokeWidth="0.65" />
          ) : (
            <path
              key={m.key}
              d={`M 32 12 A ${m.rx.toFixed(2)} 20 0 0 ${m.sweep} 32 52`}
              strokeWidth="0.65"
            />
          )
        ))}
      </g>
    </svg>
  );
}

const MATRIX_SLOTS = [
  { x: 5, y: 6 },
  { x: 18, y: 6 },
  { x: 5, y: 18 },
  { x: 18, y: 18 }
];

const MATRIX_STEPS = [
  [0, 1, 2, 3],
  [1, 3, 0, 2],
  [3, 2, 1, 0],
  [2, 0, 3, 1]
];

function AttackMatrixIcon({ isHovered }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (!isHovered) {
      setStep(0);
      return undefined;
    }

    setStep(1);
    const id = setInterval(() => {
      setStep((prev) => (prev + 1) % MATRIX_STEPS.length);
    }, 620);

    return () => clearInterval(id);
  }, [isHovered]);

  return (
    <svg width="116" height="116" viewBox="0 0 32 32" fill="none">
      {MATRIX_SLOTS.map((base, idx) => {
        const targetIdx = MATRIX_STEPS[step][idx];
        const target = MATRIX_SLOTS[targetIdx];
        const dx = target.x - base.x;
        const dy = target.y - base.y;
        const isFilledPair = idx === 0 || idx === 3;

        return (
          <rect
            key={idx}
            x={base.x}
            y={base.y}
            width="9"
            height="8"
            stroke="currentColor"
            strokeWidth="0.45"
            fill={isHovered && isFilledPair ? 'currentColor' : 'none'}
            style={{
              transform: `translate(${dx}px, ${dy}px)`,
              transition: 'transform 0.48s cubic-bezier(0.22, 1, 0.36, 1)'
            }}
          />
        );
      })}
    </svg>
  );
}

const SHIELD_PATH = 'M 32 11 L 49 17.5 V 31.5 C 49 42.5 32 53 32 53 C 32 53 15 42.5 15 31.5 V 17.5 Z';

const DAGGER_HILT = [
  'M 32 4.5',
  'C 34.2 4.5, 35.2 6.5, 35.2 9.0',
  'L 35.0 10.8',
  'L 33.5 11.3',
  'L 33.5 17.5',
  'C 33.5 18.3, 35.4 18.6, 35.4 19.5',
  'L 35.4 22.5',
  'L 28.6 22.5',
  'L 28.6 19.5',
  'C 28.6 18.6, 30.5 18.3, 30.5 17.5',
  'L 30.5 11.3',
  'L 29.0 10.8',
  'L 28.8 9.0',
  'C 28.8 6.5, 29.8 4.5, 32 4.5',
  'Z'
].join(' ');

const DAGGER_BLADE = [
  'M 29.0 22.5',
  'L 35.0 22.5',
  'L 34.4 43.0',
  'C 34.1 49.5, 33.1 55.0, 32 59.5',
  'C 30.9 55.0, 29.9 49.5, 29.6 43.0',
  'Z'
].join(' ');

function DaggerShape({ isActive }) {
  const detailStroke = isActive ? 'var(--bg)' : 'currentColor';

  return (
    <>
      {isActive && (
        <g fill="var(--bg)" stroke="var(--bg)" strokeWidth="2.4" strokeLinejoin="round">
          <path d={DAGGER_HILT} />
          <path d={DAGGER_BLADE} />
        </g>
      )}
      <g
        fill={isActive ? 'currentColor' : 'var(--bg)'}
        stroke="currentColor"
        strokeWidth={isActive ? '0.45' : '0.85'}
        strokeLinejoin="round"
      >
        <path d={DAGGER_BLADE} />
        <path d={DAGGER_HILT} />
      </g>
      <g stroke={detailStroke} strokeWidth="0.6" strokeLinecap="round" fill="none">
        <line x1="28.6" y1="22.5" x2="35.4" y2="22.5" />
        <line x1="30.5" y1="11.5" x2="33.5" y2="11.5" />
        <line x1="30.5" y1="17.4" x2="33.5" y2="17.4" />
        <circle cx="32" cy="8.3" r="0.75" />
        <circle cx="32" cy="20.2" r="0.75" />
        <line x1="32" y1="24.0" x2="32" y2="54.0" />
      </g>
    </>
  );
}

function AssuranceIcon({ isHovered }) {
  const daggerTransition = 'transform 0.45s cubic-bezier(0.22, 1, 0.36, 1)';

  return (
    <svg width="116" height="116" viewBox="0 0 64 64" fill="none">
      {/* Shield behind crossed daggers */}
      <path
        d={SHIELD_PATH}
        fill={isHovered ? 'currentColor' : 'none'}
        stroke="currentColor"
        strokeWidth="0.85"
      />

      {/* Concealed second dagger: spreads counter-clockwise to -45deg */}
      <g
        style={{
          transformOrigin: '32px 32px',
          transform: isHovered ? 'rotate(-45deg)' : 'rotate(0deg)',
          transition: daggerTransition
        }}
      >
        <DaggerShape isActive={isHovered} />
      </g>

      {/* Primary dagger: conceals the second at rest, spreads clockwise to +45deg */}
      <g
        style={{
          transformOrigin: '32px 32px',
          transform: isHovered ? 'rotate(45deg)' : 'rotate(0deg)',
          transition: daggerTransition
        }}
      >
        <DaggerShape isActive={isHovered} />
      </g>
    </svg>
  );
}

const LENSES_CONFIG = [
  {
    id: 'neural-port',
    tag: 'LENS 01 // KNOWLEDGE BRAIN',
    title: 'NEURAL PORT',
    desc: 'Interactive 3D knowledge taxonomy, machine writeups, tools, CVEs, and MITRE adversary mapping.',
    renderIcon: (isHovered) => <NeuralPortIcon isHovered={isHovered} />
  },
  {
    id: 'globe',
    tag: 'LENS 02 // EDGE TELEMETRY',
    title: 'GLOBE',
    desc: 'Real-time isolated edge threat telemetry, ingress attack vector arcs, and WAF defense rings.',
    renderIcon: (isHovered) => <GlobeIcon isHovered={isHovered} />
  },
  {
    id: 'attack-matrix',
    tag: 'LENS 03 // ADVERSARY TACTICS',
    title: 'ATT&CK MATRIX',
    desc: 'Enterprise MITRE ATT&CK coverage tracking real-time probed vs verified covered defense techniques.',
    renderIcon: (isHovered) => <AttackMatrixIcon isHovered={isHovered} />
  },
  {
    id: 'assurance',
    tag: 'LENS 04 // DEFENSIVE POSTURE',
    title: 'ASSURANCE',
    desc: 'Continuous verification of edge security controls, Zero Trust policies, and telemetry immutability.',
    renderIcon: (isHovered) => <AssuranceIcon isHovered={isHovered} />
  }
];

function LensesHub({ onSelectLens, metrics, snapshot }) {
  const [hoveredLens, setHoveredLens] = useState(null);
  const siteReq = snapshot?.traffic?.site_requests;
  const app5xx = snapshot?.errors_5xx?.app_5xx;
  const probeFamiliesCount = snapshot?.probes?.families?.length;
  const probeBlocked = snapshot?.probes?.by_outcome?.blocked;
  const isStale = Boolean(snapshot?.meta?.stale);

  const badgeByLens = {
    'neural-port': {
      text: 'CVE FEED // GRAPH',
      color: 'var(--dim)'
    },
    'globe': typeof siteReq === 'number'
      ? {
          text: `${siteReq} SITE · ${app5xx ?? 0} APP 5XX`,
          color: (app5xx ?? 0) > 0 ? '#c00030' : 'var(--mitre)'
        }
      : {
          text: metrics ? `${metrics.worker_requests_24h} REQ · ${metrics.blocked_403} BLK` : 'EDGE // LIVE',
          color: 'var(--warn)'
        },
    'attack-matrix': typeof probeFamiliesCount === 'number'
      ? {
          text: `${probeFamiliesCount} FAMILIES · ${probeBlocked ?? 0} BLK`,
          color: (probeBlocked ?? 0) > 0 ? 'var(--warn)' : 'var(--mitre)'
        }
      : {
          text: 'MITRE // ENTERPRISE',
          color: 'var(--dim)'
        },
    'assurance': snapshot?.meta || snapshot?.errors_5xx
      ? {
          text: `${isStale ? 'STALE' : 'FRESH'} · ${app5xx ?? 0} APP 5XX`,
          color: isStale || (app5xx ?? 0) > 0 ? 'var(--warn)' : 'var(--mitre)'
        }
      : {
          text: '6 CONTROLS // PASS',
          color: 'var(--mitre)'
        }
  };

  return (
    <div style={{
      position: 'relative',
      width: '100%',
      height: '100%',
      display: 'grid',
      gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
      gridTemplateRows: 'repeat(2, minmax(0, 1fr))',
      gap: 0,
      padding: 0,
      boxSizing: 'border-box',
      background: 'var(--bg)'
    }}>
      {LENSES_CONFIG.map((lens) => {
        const isHovered = hoveredLens === lens.id;
        return (
          <div
            key={lens.id}
            onClick={() => onSelectLens(lens.id)}
            onMouseEnter={() => setHoveredLens(lens.id)}
            onMouseLeave={() => setHoveredLens(null)}
            style={{
              position: 'relative',
              backgroundColor: 'transparent',
              padding: '28px 32px 24px 32px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              cursor: 'pointer',
              fontFamily: "'JetBrains Mono', ui-monospace, monospace",
              overflow: 'hidden'
            }}
          >
            {/* Top header */}
            <div>
              <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '9px', color: 'var(--dim)', letterSpacing: '0.12em', fontWeight: 'bold' }}>
                  {lens.tag}
                </span>
                {badgeByLens[lens.id] && (
                  <span style={{ fontSize: '9px', color: badgeByLens[lens.id].color, letterSpacing: '0.06em', fontWeight: 'bold', whiteSpace: 'nowrap' }}>
                    {badgeByLens[lens.id].text}
                  </span>
                )}
              </div>

              <h3 style={{
                fontSize: '15px',
                color: 'var(--fg-bright)',
                letterSpacing: '0.06em',
                margin: '0 0 8px 0',
                fontWeight: '600'
              }}>
                {lens.title}
              </h3>

              <p style={{
                fontSize: '11px',
                color: 'var(--dim)',
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
              padding: '16px 0 8px 0',
              color: '#c00030'
            }}>
              {lens.renderIcon(isHovered)}
            </div>

            {/* Bottom action */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '10px',
              color: isHovered ? '#c00030' : 'var(--dim)',
              letterSpacing: '0.08em',
              fontWeight: 'bold',
              marginTop: '12px',
              opacity: 1,
              transition: 'color 0.18s ease'
            }}>
              <span>ENGAGE LENS</span>
              <span>[ ↗ ]</span>
            </div>
          </div>
        );
      })}

      {/* Inset vertical and horizontal cross dividing lines */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          left: '50%',
          top: '28px',
          bottom: '28px',
          width: 0,
          borderLeft: '1px solid var(--line)',
          pointerEvents: 'none',
          zIndex: 2
        }}
      />
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          top: '50%',
          left: '28px',
          right: '28px',
          height: 0,
          borderTop: '1px solid var(--line)',
          pointerEvents: 'none',
          zIndex: 2
        }}
      />

      {/* Central axial intersection fiducial (o) */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          left: '50%',
          top: '50%',
          transform: 'translate(-50%, -50%)',
          width: '24px',
          height: '24px',
          borderRadius: '50%',
          background: 'var(--bg)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          pointerEvents: 'none',
          zIndex: 5
        }}
      >
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <circle
            cx="7"
            cy="7"
            r="4.5"
            stroke={hoveredLens ? '#c00030' : 'var(--dim)'}
            strokeWidth="1"
            style={{ transition: 'stroke 0.18s ease' }}
          />
        </svg>
      </div>
    </div>
  );
}

export default React.memo(LensesHub);
