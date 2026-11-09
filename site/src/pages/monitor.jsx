import React, { useState, useEffect, Suspense, lazy } from 'react';
import Layout from '@theme/Layout';
import BrowserOnly from '@docusaurus/BrowserOnly';
import styles from './index.module.css';
import '../css/neural-graph.css';
import { countryCoords } from '../components/countryCoords';

const SecurityGlobe = lazy(() => import('../components/SecurityGlobe'));

export default function MonitorPage() {
  const [data, setData] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const [lastSync, setLastSync] = useState('0000-00-00 00:00 GMT+4');
  const [displaySync, setDisplaySync] = useState('0000-00-00 00:00 GMT+4');
  const [isAnimating, setIsAnimating] = useState(false);
  const [activeTab, setActiveTab] = useState('countries');
  const [viewMode, setViewMode] = useState('traffic');
  const [onlyBots, setOnlyBots] = useState(false);

  const [focusCoords, setFocusCoords] = useState(null);
  const [focusCountry, setFocusCountry] = useState(null);
  const [focusPath, setFocusPath] = useState(null);

  const [layers, setLayers] = useState({
    timeline: true, shield: true, threats: true, atmosphere: true,
  });

  const toggleLayer = (key) => {
    setLayers(prev => ({ ...prev, [key]: !prev[key] }));
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const apiUrl = typeof window !== 'undefined' && window.location.hostname === 'localhost'
          ? 'http://localhost:8787'
          : 'https://bugterium-security-monitor.bugterium.workers.dev';
        const response = await fetch(apiUrl);
        const result = await response.json();
        if (result.status === 'ok') {
          setData(result);
          setIsLive(true);
          const now = new Date();
          const gmt4 = new Date(now.getTime() + (4 * 60 * 60 * 1000));
          const formatted = gmt4.toISOString().replace('T', ' ').substring(0, 16) + ' GMT+4';
          setLastSync(formatted);
        }
      } catch (error) {
        setIsLive(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    setIsAnimating(true);
    const target = lastSync;
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*';
    let frame = 0;
    const interval = setInterval(() => {
      frame += 0.2;
      const revealed = target.slice(0, Math.floor(frame));
      const scrambled = target.slice(Math.floor(frame)).split('').map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
      setDisplaySync(revealed + scrambled);
      if (frame >= target.length) clearInterval(interval);
    }, 30);
    return () => clearInterval(interval);
  }, [lastSync]);

  if (!data) {
    return (
      <Layout title="Security Monitor" description="Live Threat Intelligence" noFooter={true}>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', color: '#c00030', fontFamily: 'JetBrains Mono, monospace', background: '#000' }}>
          INITIALIZING SECURITY FEED...
        </div>
      </Layout>
    );
  }

  const { security_metrics, geo_data, attacks_by_country, timeline, path_data, user_agent_data, status_breakdown } = data;

  const renderBreakdown = (prefix, color) => {
    if (!status_breakdown) return null;
    const filtered = status_breakdown.filter(s => s.code >= prefix * 100 && s.code < (prefix + 1) * 100).sort((a, b) => a.code - b.code);
    if (filtered.length === 0) return <div style={{ fontSize: '10px', color: '#666', marginTop: '5px' }}>No errors</div>;
    return (
      <div style={{ display: 'grid', gridAutoFlow: 'column', gridTemplateRows: 'repeat(' + Math.ceil(filtered.length / 2) + ', auto)', gap: '4px 15px', marginTop: '5px' }}>
        {filtered.map(s => (
          <div key={s.code} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: color, borderBottom: '1px solid #222', paddingBottom: '2px', paddingLeft: '4px', paddingRight: '4px' }}>
            <span>{s.code}</span>
            <span>{s.count}</span>
          </div>
        ))}
      </div>
    );
  };

  const baseCountries = viewMode === 'attacks' ? attacks_by_country : geo_data;
  const basePaths = viewMode === 'attacks' ? path_data.attacks : path_data.benign;

  let displayGeoData = baseCountries;
  let filteredPaths = basePaths;
  let filteredCountries = baseCountries;

  const botRe = /bot|crawl|spider|slurp|curl|wget|python|go-http|java\/|okhttp|axios|node-fetch|headless|phantom|puppet|selenium|playwright|masscan|nmap|nikto|sqlmap|zgrab|censys|shodan|expanse|nuclei|httpx|feroxbuster|gobuster|dirb|dirbuster|ffuf/i;

  const filteredAgents = onlyBots ? user_agent_data[viewMode].filter(a => botRe.test(a.ua)) : user_agent_data[viewMode];

  if (focusPath && path_data.correlations[focusPath]) {
    displayGeoData = Object.entries(path_data.correlations[focusPath])
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count);
    filteredCountries = displayGeoData;
  } else if (focusCountry) {
    filteredPaths = basePaths.filter(item => {
      const corr = path_data.correlations[item.path];
      return corr && corr[focusCountry];
    }).map(item => ({
      ...item,
      count: path_data.correlations[item.path][focusCountry]
    })).sort((a, b) => b.count - a.count);
  }

  const legendItemStyle = (isActive) => ({
    display: 'flex', alignItems: 'center', cursor: 'pointer',
    opacity: isActive ? 1 : 0.3, transition: 'opacity 0.2s'
  });

  const tabButtonStyle = (tabName) => ({
    background: 'none', border: 'none', fontFamily: 'JetBrains Mono, monospace',
    fontSize: '11px', cursor: 'pointer', padding: '0', fontWeight: activeTab === tabName ? 'bold' : 'normal',
    color: activeTab === tabName ? '#c00030' : '#666',
    transition: 'all 0.2s'
  });

  const handleTabClick = (tab) => {
    setActiveTab(tab);
    setFocusPath(null);
    setFocusCountry(null);
    setFocusCoords(null);
  };

  const handlePathClick = (path) => {
    if (focusPath === path) {
      setFocusPath(null);
    } else {
      setFocusPath(path);
      setFocusCountry(null);
      setFocusCoords(null);
    }
  };

  return (
    <Layout title="Bugterium / SECURITY MONITOR" description="Live Threat Intelligence" noFooter={true}>
      <div className={styles.layout}>
        
        {/* ЛЕВАЯ КОЛОНКА */}
        <div className={styles.leftCol}>
          <div className={styles.card}>
            <div className={styles.cardLabel} style={{ fontSize: "16px" }}>REQUESTS (24H)</div>
            <div className={styles.cardDesc} style={{ fontSize: "28px", color: "#ff8c00", marginTop: "10px", fontWeight: "bold" }}>{security_metrics.worker_requests_24h}</div>
          </div>
          <div className={styles.card}>
            <div className={styles.cardLabel}>CLIENT ERRORS</div>
            <div className={styles.cardDesc} style={{ fontSize: '28px', color: security_metrics.client_errors_4xx > 0 ? '#ff8c00' : '#fff', marginTop: '10px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px', paddingLeft: '4px' }}>{security_metrics.client_errors_4xx || 0}</div>
            <div style={{ marginTop: '10px' }}>{renderBreakdown(4, '#ff8c00')}</div>
          </div>
          <div className={styles.card}>
            <div className={styles.cardLabel}>SERVER ERRORS</div>
            <div className={styles.cardDesc} style={{ fontSize: '28px', color: security_metrics.server_errors_5xx > 0 ? '#ff8c00' : '#fff', marginTop: '10px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px', paddingLeft: '4px' }}>{security_metrics.server_errors_5xx || 0}</div>
            <div style={{ marginTop: '10px' }}>{renderBreakdown(5, '#ff8c00')}</div>
          </div>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
            <div className={styles.card} style={{ flex: 1, minWidth: 0, textAlign: 'center' }}>
              <div className={styles.cardLabel} style={{ fontSize: '12px', letterSpacing: '0.05em', margin: 0 }}>LEGITIMATE</div>
              <div className={styles.cardDesc} style={{ fontSize: '28px', color: '#ff8c00', marginTop: '4px', fontWeight: 'bold' }}>[ {security_metrics.health_percent || '100.0'}% ]</div>
            </div>
            <div className={styles.card} style={{ flex: 1, minWidth: 0, textAlign: 'center' }}>
              <div className={styles.cardLabel} style={{ fontSize: '12px', letterSpacing: '0.05em', margin: 0 }}>SUSPICIOUS</div>
              <div className={styles.cardDesc} style={{ fontSize: '28px', color: '#ff8c00', marginTop: '4px', fontWeight: 'bold' }}>[ {(100 - parseFloat(security_metrics.health_percent || '100.0')).toFixed(1)}% ]</div>
            </div>
          </div>
        </div>

        {/* ЦЕНТРАЛЬНАЯ КОЛОНКА */}
        <div className={styles.centerCol}>
          <div className="app">
            <header className="hud">
              <span className="brand"><span className="brand-prefix">BUGTERIUM</span><span className="sep">/</span> SECURITY MONITOR</span>
              <nav className="crumbs">
                <span className="crumb-item">
                  <button type="button" className="crumb active">
                    {focusPath ? `PATH: ${focusPath}` : (focusCountry ? `FOCUS: ${focusCountry}` : (isLive ? 'LIVE' : 'OFFLINE'))}
                  </button>
                </span>
              </nav>
            <span className="status">{security_metrics.worker_requests_24h} REQUESTS / {security_metrics.blocked_403} BLOCKED</span>
            </header>
            <main className="stage">
              {/* ИНТЕРАКТИВНАЯ ЛЕГЕНДА */}
              <div style={{ position: 'absolute', top: '20px', left: '20px', zIndex: 10, display: 'flex', flexDirection: 'column', gap: '9px', fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#888', userSelect: 'none' }}>
                {[
                  { key: 'threats', label: 'Events', color: '#ff8c00' },
                  { key: 'shield', label: 'Defense In Depth', color: '#0000ff' },
                  { key: 'timeline', label: '24H Traffic Timeline', color: '#a855f7' }
                ].map(item => (
                  <div key={item.key} style={legendItemStyle(layers[item.key])} onClick={() => toggleLayer(item.key)}>
                    <svg width="8" height="8" style={{ marginRight: '6px', flexShrink: 0 }}>
                      <circle cx="4" cy="4" r="4" fill={layers[item.key] ? item.color : '#666'} />
                    </svg>
                    <span style={{ lineHeight: 1, transform: 'translateY(1px)' }}>{item.label}</span>
                  </div>
                ))}
              </div>

              {/* Дисклеймер в стиле Neural Port */}
              <div style={{ position: 'absolute', bottom: '17px', left: '20px', zIndex: 10, fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', letterSpacing: '0.05em', color: '#c00030', pointerEvents: 'none', lineHeight: '1.6' }}>
                <div>Aggregated real-world traffic data.</div>
                <div>No PII or IP addresses collected.</div>
                <div>Fully anonymized.</div>
              </div>

              <BrowserOnly fallback={<div style={{ background: '#000', height: '100%' }} />}>
                {() => (
                  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#c00030', fontFamily: 'JetBrains Mono, monospace' }}>Loading 3D Globe...</div>}>
                    <SecurityGlobe geoData={displayGeoData} focusCoords={focusCoords} focusCountry={focusCountry} metrics={security_metrics} timeline={timeline} layers={layers} onCountryClick={(country) => { if (focusCountry === country) { setFocusCountry(null); setFocusCoords(null); } else { setFocusCountry(country); setFocusCoords({ lat: countryCoords[country][0], lng: countryCoords[country][1] }); } setFocusPath(null); }} />
                  </Suspense>
                )}
              </BrowserOnly>
            </main>
          </div>
        </div>

        {/* ПРАВАЯ КОЛОНКА */}
        <div className={styles.rightCol}>
          <div className={styles.threatsHeader}>TOP SOURCES</div>

          {/* Переключатель режима */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', marginBottom: '15px', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#666' }}>
            <span>MODE:</span>
            <div style={{ display: 'flex', gap: '15px' }}>
              <button
                onClick={() => { setViewMode('traffic'); setFocusPath(null); setFocusCountry(null); setFocusCoords(null); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', padding: '0', color: viewMode === 'traffic' ? '#c00030' : '#666', fontWeight: viewMode === 'traffic' ? 'bold' : 'normal' }}
              >
                [ ALL TRAFFIC ]
              </button>
              <button
                onClick={() => { setViewMode('attacks'); setFocusPath(null); setFocusCountry(null); setFocusCoords(null); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', padding: '0', color: viewMode === 'attacks' ? '#c00030' : '#666', fontWeight: viewMode === 'attacks' ? 'bold' : 'normal' }}
              >
                [ SUSPICIOUS ACTIVITY ]
              </button>
            </div>
          </div>

          {/* Вкладки внутри режима */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', marginBottom: '15px', borderBottom: '1px solid #1a1a1a', paddingBottom: '15px', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#666' }}>
            <span>FILTER BY:</span>
            <div style={{ display: 'flex', gap: '15px', flexWrap: 'wrap', alignItems: 'flex-start', marginBottom: activeTab === 'agents' ? '30px' : '0px' }}>
              <button style={tabButtonStyle('countries')} onClick={() => handleTabClick('countries')}>[ COUNTRIES ]</button>
              <button style={tabButtonStyle('paths')} onClick={() => handleTabClick('paths')}>[ PATHS ]</button>
              <div style={{ display: 'flex', flexDirection: 'column', position: 'relative' }}>
                <button style={tabButtonStyle('agents')} onClick={() => handleTabClick('agents')}>[ USER AGENTS ]</button>
                {activeTab === 'agents' && (
                  <button onClick={() => setOnlyBots(prev => !prev)} style={{ background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', padding: '0', position: 'absolute', top: '24px', left: '50%', transform: 'translateX(-50%)', color: onlyBots ? '#800020' : '#333', fontWeight: onlyBots ? 'bold' : 'normal', whiteSpace: 'nowrap' }}>ONLY BOTS</button>
                )}
              </div>
            </div>
          </div>

          <div className={styles.threatList}>
            {/* Вкладка СТРАНЫ */}
            {activeTab === 'countries' && filteredCountries.slice(0, 10).map((item, idx) => {
              const hasCoords = item.country !== 'XX' && !!countryCoords[item.country];
              const displayCountry = item.country === 'XX' ? 'UNKNOWN' : item.country;
              const isFocused = focusCountry === item.country;
              return (
                <div key={idx} className={styles.threatCard} style={{ cursor: hasCoords ? 'pointer' : 'default', opacity: hasCoords ? (focusCountry && !isFocused ? 0.4 : 1) : 0.5, borderColor: isFocused ? '#c00030' : undefined, backgroundColor: isFocused ? 'rgba(192, 0, 48, 0.1)' : undefined, transition: 'all 0.3s ease' }} onClick={() => {
                  if (hasCoords) {
                    if (isFocused) { setFocusCountry(null); setFocusCoords(null); }
                    else { setFocusCountry(item.country); setFocusCoords({ lat: countryCoords[item.country][0], lng: countryCoords[item.country][1] }); setFocusPath(null); }
                  }
                }}>
                  <div className={styles.threatHeader}>
                    <div className={styles.threatId} style={{ color: isFocused ? '#fff' : undefined }}>{displayCountry}</div>
                    <div className={styles.threatRight}><div className={styles.threatCvss} style={{ color: isFocused ? '#fff' : undefined }}>{item.count}</div></div>
                  </div>
                </div>
              );
            })}

            {/* Вкладка ПУТИ */}
            {activeTab === 'paths' && filteredPaths.slice(0, 15).map((item, idx) => {
              const isFocused = focusPath === item.path;
              return (
                <div key={idx} className={styles.threatCard} style={{ cursor: 'pointer', borderColor: isFocused ? '#c00030' : undefined, backgroundColor: isFocused ? 'rgba(192, 0, 48, 0.1)' : undefined }} onClick={() => handlePathClick(item.path)}>
                  <div className={styles.threatHeader}>
                    <div className={styles.threatId} style={{ fontSize: '11px', wordBreak: 'break-all', color: isFocused ? '#fff' : undefined }}>{item.path}</div>
                    <div className={styles.threatRight}><div className={styles.threatCvss} style={{ color: isFocused ? '#fff' : undefined }}>{item.count}</div></div>
                  </div>
                </div>
              );
            })}

            {/* Вкладка АГЕНТЫ */}
            {activeTab === 'agents' && filteredAgents.slice(0, 10).map((item, idx) => (
              <div key={idx} className={styles.threatCard} title={item.ua}>
                <div className={styles.threatHeader}>
                  <div className={styles.threatId} style={{ fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }}>{item.ua}</div>
                  <div className={styles.threatRight}><div className={styles.threatCvss}>{item.count}</div></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ФУТЕРЫ */}
        <div className={styles.leftFooter} style={{ display: 'flex', alignItems: 'center' }}>
          <svg width='14' height='14' viewBox='0 0 14 14' style={{ marginRight: '8px', transform: 'translateY(-0.5px)' }}>
            <circle cx='7' cy='7' r='5' fill='none' stroke='currentColor' strokeWidth='1' />
            {isLive && (<circle cx='7' cy='7' r='2.5' fill='#c00030' />)}
          </svg>
          {isLive ? 'SYSTEM READY' : 'OFFLINE'}
        </div>
        <div className={styles.centerFooter}>LEFT-CLICK: ROTATE · MOUSE-WHEEL: ZOOM</div>
        <div className={styles.rightFooter} style={{ display: 'block', textAlign: 'center', width: '100%', padding: '10px 0' }}>
          <span style={{ display: 'inline-block', position: 'relative', transform: 'translateX(-6px)', whiteSpace: 'nowrap' }}>
            <span style={{ visibility: 'hidden', fontWeight: 'bold' }}><span>LIVE SYNC:</span> 0000-00-00 00:00 GMT+4</span>
            <span style={{ position: 'absolute', left: 0, top: 0 }}>
              <span className={isAnimating ? styles.blink : ''} style={{ color: '#c00030', fontWeight: 'bold', transition: 'opacity 0.5s ease-out' }}>LIVE SYNC:</span> {displaySync}
            </span>
          </span>
        </div>

      </div>
    </Layout>
  );
}
