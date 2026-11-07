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
  
  const [focusCoords, setFocusCoords] = useState(null);
  const [focusCountry, setFocusCountry] = useState(null);

  // Состояние видимости слоев (все включены по умолчанию)
  const [layers, setLayers] = useState({
    timeline: true,
    traffic: true,
    scanner: true,
    shield: true,
    threats: true,
    atmosphere: true,
  });

  const toggleLayer = (key) => {
    setLayers(prev => ({ ...prev, [key]: !prev[key] }));
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('https://bugterium-security-monitor.bugterium.workers.dev');
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
      if (frame >= target.length) {
        clearInterval(interval);
      }
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

  const { security_metrics, geo_data, timeline } = data;

  // Вспомогательная функция для стилизации легенды
  const legendItemStyle = (isActive) => ({
    display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer',
    opacity: isActive ? 1 : 0.3, transition: 'opacity 0.2s'
  });

  return (
    <Layout title="Bugterium / SECURITY MONITOR" description="Live Threat Intelligence" noFooter={true}>
      <div className={styles.layout}>

        {/* ЛЕВАЯ КОЛОНКА */}
        <div className={styles.leftCol}>
          <div className={styles.card}>
            <div className={styles.cardLabel}>REQUESTS (24H)</div>
            <div className={styles.cardDesc} style={{ fontSize: '28px', color: '#fff', marginTop: '10px', fontWeight: 'bold' }}>
              {security_metrics.worker_requests_24h}
            </div>
          </div>
          <div className={styles.card}>
            <div className={styles.cardLabel}>ERRORS</div>
            <div className={styles.cardDesc} style={{ fontSize: '28px', color: security_metrics.worker_errors_24h > 0 ? '#ff003c' : '#00ff00', marginTop: '10px', fontWeight: 'bold' }}>
              {security_metrics.worker_errors_24h}
            </div>
          </div>
          <div className={styles.card}>
            <div className={styles.cardLabel}>BLOCKED (403)</div>
            <div className={styles.cardDesc} style={{ fontSize: '28px', color: security_metrics.blocked_403 > 0 ? '#c00030' : '#fff', marginTop: '10px', fontWeight: 'bold' }}>
              {security_metrics.blocked_403}
            </div>
          </div>
          <div className={styles.card}>
            <div className={styles.cardLabel}>RATE LIMITED</div>
            <div className={styles.cardDesc} style={{ fontSize: '28px', color: '#fff', marginTop: '10px', fontWeight: 'bold' }}>
              {security_metrics.blocked_429}
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
                    {focusCountry ? `FOCUS: ${focusCountry}` : (isLive ? 'LIVE' : 'OFFLINE')}
                  </button>
                </span>
              </nav>
              <span className="status">{security_metrics.worker_requests_24h} REQUESTS / {security_metrics.blocked_403} BLOCKED</span>
            </header>
            <main className="stage">
              
              {/* ИНТЕРАКТИВНАЯ ЛЕГЕНДА */}
              <div style={{ position: 'absolute', top: '20px', left: '20px', zIndex: 10, display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', color: '#fff', userSelect: 'none' }}>
                <div style={legendItemStyle(layers.timeline)} onClick={() => toggleLayer('timeline')}>
                  <span style={{ color: layers.timeline ? '#ff003c' : '#666', fontSize: '14px', transition: 'color 0.2s' }}>●</span> 24H TIMELINE
                </div>
                <div style={legendItemStyle(layers.traffic)} onClick={() => toggleLayer('traffic')}>
                  <span style={{ color: layers.traffic ? '#00ffff' : '#666', fontSize: '14px', transition: 'color 0.2s' }}>●</span> EDGE TRAFFIC
                </div>
                <div style={legendItemStyle(layers.scanner)} onClick={() => toggleLayer('scanner')}>
                  <span style={{ color: layers.scanner ? '#00ffcc' : '#666', fontSize: '14px', transition: 'color 0.2s' }}>●</span> ACTIVE SCANNER
                </div>
                <div style={legendItemStyle(layers.shield)} onClick={() => toggleLayer('shield')}>
                  <span style={{ color: layers.shield ? '#00ff00' : '#666', fontSize: '14px', transition: 'color 0.2s' }}>●</span> DEFENSE SHIELD
                </div>
                <div style={legendItemStyle(layers.threats)} onClick={() => toggleLayer('threats')}>
                  <span style={{ color: layers.threats ? '#ff8c00' : '#666', fontSize: '14px', transition: 'color 0.2s' }}>●</span> THREAT SOURCES
                </div>
                <div style={legendItemStyle(layers.atmosphere)} onClick={() => toggleLayer('atmosphere')}>
                  <span style={{ color: layers.atmosphere ? '#a855f7' : '#666', fontSize: '14px', transition: 'color 0.2s' }}>●</span> ATMOSPHERE
                </div>
              </div>

              <BrowserOnly fallback={<div style={{ background: '#000', height: '100%' }} />}>
                {() => (
                  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#c00030', fontFamily: 'JetBrains Mono, monospace' }}>Loading 3D Globe...</div>}>
                    <SecurityGlobe 
                      geoData={geo_data} 
                      focusCoords={focusCoords} 
                      focusCountry={focusCountry} 
                      metrics={security_metrics} 
                      timeline={timeline}
                      layers={layers} /* ПЕРЕДАЕМ СОСТОЯНИЕ СЛОЕВ */
                    />
                  </Suspense>
                )}
              </BrowserOnly>
            </main>
          </div>
        </div>

        {/* ПРАВАЯ КОЛОНКА */}
        <div className={styles.rightCol}>
          <div className={styles.threatsHeader}>TOP SOURCES</div>
          <div className={styles.threatList}>
            {geo_data.slice(0, 10).map((item, idx) => {
              const hasCoords = !!countryCoords[item.country];
              const isFocused = focusCountry === item.country;
              
              return (
                <div 
                  key={idx} 
                  className={styles.threatCard}
                  style={{ 
                    cursor: hasCoords ? 'pointer' : 'default',
                    opacity: hasCoords ? (focusCountry && !isFocused ? 0.4 : 1) : 0.5,
                    borderColor: isFocused ? '#c00030' : undefined,
                    backgroundColor: isFocused ? 'rgba(192, 0, 48, 0.1)' : undefined,
                    transition: 'all 0.3s ease'
                  }}
                  onClick={() => {
                    if (hasCoords) {
                      if (isFocused) {
                        setFocusCountry(null);
                        setFocusCoords(null);
                      } else {
                        setFocusCountry(item.country);
                        setFocusCoords({ lat: countryCoords[item.country][0], lng: countryCoords[item.country][1] });
                      }
                    }
                  }}
                >
                  <div className={styles.threatHeader}>
                    <div className={styles.threatId} style={{ color: isFocused ? '#fff' : undefined }}>{item.country}</div>
                    <div className={styles.threatRight}>
                      <div className={styles.threatCvss} style={{ color: isFocused ? '#fff' : undefined }}>{item.count}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ФУТЕРЫ */}
        <div className={styles.leftFooter} style={{ display: 'flex', alignItems: 'center' }}>
          <svg width='14' height='14' viewBox='0 0 14 14' style={{ marginRight: '8px', transform: 'translateY(-0.5px)' }}>
            <circle cx='7' cy='7' r='5' fill='none' stroke='currentColor' strokeWidth='1' />
            {isLive && (
              <circle cx='7' cy='7' r='2.5' fill='#c00030' />
            )}
          </svg>
          {isLive ? 'SYSTEM READY' : 'OFFLINE'}
        </div>

        <div className={styles.centerFooter}>LEFT-CLICK: ROTATE · MOUSE-WHEEL: ZOOM</div>

        <div className={styles.rightFooter} style={{ display: 'block', textAlign: 'center', width: '100%', padding: '10px 0' }}>
          <span style={{ display: 'inline-block', position: 'relative', transform: 'translateX(-6px)', whiteSpace: 'nowrap' }}>
            <span style={{ visibility: 'hidden', fontWeight: 'bold' }}>
              <span>LIVE SYNC:</span> 0000-00-00 00:00 GMT+4
            </span>
            <span style={{ position: 'absolute', left: 0, top: 0 }}>
              <span className={isAnimating ? styles.blink : ''} style={{ color: '#c00030', fontWeight: 'bold', transition: 'opacity 0.5s ease-out' }}>LIVE SYNC:</span> {displaySync}
            </span>
          </span>
        </div>

      </div>
    </Layout>
  );
}