import React, { useState, useEffect, Suspense, lazy } from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';
import Link from '@docusaurus/Link';
import { useLocation, useHistory } from '@docusaurus/router';
import styles from '../pages/index.module.css';
import '../css/neural-graph.css';
import { countryCoords } from './countryCoords';
import LiveThreats from './LiveThreats';
import LensesHub from './LensesHub';

const SecurityGlobe = lazy(() => import('./SecurityGlobe'));
const NeuralGraph = lazy(() => import('./NeuralGraph'));
const AttackMatrix = lazy(() => import('./AttackMatrix'));
const AssuranceView = lazy(() => import('./AssuranceView'));

const FALLBACK_DATA = {
  status: 'ok',
  timestamp: new Date().toISOString(),
  security_metrics: {
    worker_requests_24h: 476,
    worker_errors_24h: 0,
    blocked_403: 42,
    blocked_429: 0,
    client_errors_4xx: 82,
    server_errors_5xx: 260,
    health_percent: '84.2'
  },
  status_breakdown: [
    { code: 200, count: 1054 },
    { code: 304, count: 1037 },
    { code: 400, count: 0 },
    { code: 401, count: 8 },
    { code: 403, count: 42 },
    { code: 404, count: 36 },
    { code: 405, count: 1 },
    { code: 413, count: 0 },
    { code: 414, count: 0 },
    { code: 422, count: 0 },
    { code: 429, count: 0 },
    { code: 451, count: 0 },
    { code: 499, count: 3 },
    { code: 500, count: 0 },
    { code: 501, count: 0 },
    { code: 502, count: 0 },
    { code: 503, count: 0 },
    { code: 504, count: 260 },
    { code: 505, count: 0 }
  ],
  geo_data: [
    { country: 'AZ', count: 1717 },
    { country: 'US', count: 1415 },
    { country: 'NL', count: 68 },
    { country: 'ID', count: 9 },
    { country: 'DE', count: 9 },
    { country: 'PL', count: 5 },
    { country: 'GB', count: 4 }
  ],
  attacks_by_country: [
    { country: 'NL', count: 24 },
    { country: 'US', count: 14 },
    { country: 'DE', count: 4 }
  ],
  timeline: Array.from({ length: 24 }).map((_, i) => ({
    hour: `${i}:00`,
    count: Math.floor(15 + Math.sin(i) * 10 + 5)
  })),
  path_data: {
    attacks: [
      { path: '/.env', count: 12 },
      { path: '/wp-login.php', count: 8 },
      { path: '/xmlrpc.php', count: 6 },
      { path: '/actuator/health', count: 5 },
      { path: '/phpmyadmin', count: 3 }
    ],
    benign: [
      { path: '/', count: 1250 },
      { path: '/monitor', count: 476 },
      { path: '/reference', count: 210 },
      { path: '/writeups', count: 180 }
    ],
    correlations: {
      '/.env': { NL: 8, US: 4 },
      '/wp-login.php': { NL: 6, DE: 2 }
    }
  },
  user_agent_data: {
    traffic: [
      { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0', count: 1100 },
      { ua: 'curl/8.0', count: 45 }
    ],
    attacks: [
      { ua: 'sqlmap/1.7', count: 10 },
      { ua: 'nikto/2.1', count: 8 }
    ]
  }
};

const getPathFamily = (path) => {
  if (path.includes('.env') || path.includes('.git') || path.includes('config') || path.includes('id_rsa')) {
    return { name: 'SECRET LEAK', color: '#c00030' };
  }
  if (path.includes('wp-') || path.includes('xmlrpc') || path.includes('wordpress')) {
    return { name: 'WORDPRESS PROBE', color: '#ff8c00' };
  }
  if (path.includes('actuator') || path.includes('api/') || path.includes('swagger')) {
    return { name: 'API EXPOSURE', color: '#a855f7' };
  }
  if (path.includes('phpmyadmin') || path.includes('mysql') || path.includes('adminer')) {
    return { name: 'DATABASE PROBE', color: '#a855f7' };
  }
  if (path === '/[hex32]' || /^\/[0-9a-f]{32}$/i.test(path)) {
    return { name: 'HEX32 PROBE', color: '#a855f7' };
  }
  return { name: 'SUSPICIOUS URI', color: '#6a6a6a' };
};

const getUaCategory = (ua) => {
  const low = ua.toLowerCase();
  if (low.includes('sqlmap') || low.includes('nikto') || low.includes('nmap') || low.includes('masscan') || low.includes('nuclei') || low.includes('ffuf') || low.includes('dirb')) {
    return { name: 'ATTACK TOOL', color: '#c00030' };
  }
  if (low.includes('python') || low.includes('curl') || low.includes('wget') || low.includes('go-http') || low.includes('axios') || low.includes('node-fetch')) {
    return { name: 'AUTOMATION SCRIPT', color: '#ff8c00' };
  }
  if (low.includes('censys') || low.includes('shodan') || low.includes('expanse') || low.includes('zgrab')) {
    return { name: 'CYBER RECON / SCANNER', color: '#a855f7' };
  }
  if (low.includes('bot') || low.includes('crawl') || low.includes('spider')) {
    return { name: 'WEB CRAWLER', color: '#6a6a6a' };
  }
  return { name: 'UNKNOWN CLIENT', color: '#333333' };
};

export default function OperationalCockpit({ defaultLens = null }) {
  const location = useLocation();
  const history = useHistory();
  const [activeLens, setActiveLensState] = useState(defaultLens);
  const [lensMountKey, setLensMountKey] = useState(0);
  const [data, setData] = useState(FALLBACK_DATA);
  const [isLive, setIsLive] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // CVE Threat feed sync state (Нейропорт)
  const [cveSync, setCveSync] = useState(null);
  const [displayCveSync, setDisplayCveSync] = useState('0000-00-00 00:00 GMT+4');
  const [isCveAnimating, setIsCveAnimating] = useState(false);
  const [isGraphReady, setIsGraphReady] = useState(false);
  const [isTextReady, setIsTextReady] = useState(false);

  // Cloudflare Edge telemetry sync state (Глобус, Хаб)
  const [telemetrySync, setTelemetrySync] = useState(null);
  const [displayTelemetrySync, setDisplayTelemetrySync] = useState('0000-00-00 00:00 GMT+4');
  const [isTelemetryAnimating, setIsTelemetryAnimating] = useState(false);
  
  // Globe specific telemetry states
  const [viewMode, setViewMode] = useState('traffic');
  const [activeTab, setActiveTab] = useState('countries');
  const [focusCountry, setFocusCountry] = useState(null);
  const [focusCoords, setFocusCoords] = useState(null);
  const [focusPath, setFocusPath] = useState(null);
  const [onlyBots, setOnlyBots] = useState(false);
  const [layers, setLayers] = useState({
    threats: true,
    shield: true,
    timeline: true,
    arcs: true
  });

  const toggleLayer = (layerKey) => {
    setLayers(prev => {
      const nextVal = !prev[layerKey];
      if (layerKey === 'threats') {
        return { ...prev, threats: nextVal, arcs: nextVal };
      }
      return { ...prev, [layerKey]: nextVal };
    });
  };

  // URL sync helper
  const setActiveLens = (lens) => {
    if (lens === activeLens) return;
    setActiveLensState(lens);
    if (lens === 'neural-port') {
      setIsGraphReady(false);
      setIsTextReady(false);
      setIsCveAnimating(true);
      setDisplayCveSync('0000-00-00 00:00 GMT+4');
      setLensMountKey(k => k + 1);
    }
    const path = lens ? `/?lens=${lens}` : '/';
    if (history && history.push) {
      history.push(path);
    } else if (typeof window !== 'undefined') {
      const url = new URL(window.location.href);
      if (lens) {
        url.searchParams.set('lens', lens);
      } else {
        url.searchParams.delete('lens');
      }
      window.history.pushState({}, '', url.toString());
    }
  };

  // Sync with router location (e.g. top navbar clicks, browser Back/Forward)
  useEffect(() => {
    const p = new URLSearchParams(location.search);
    const l = p.get('lens') || defaultLens || null;
    setActiveLensState(prev => {
      if (prev !== l) {
        if (l === 'neural-port') {
          setIsGraphReady(false);
          setIsTextReady(false);
          setIsCveAnimating(true);
          setDisplayCveSync('0000-00-00 00:00 GMT+4');
          setLensMountKey(k => k + 1);
        }
        return l;
      }
      return prev;
    });
  }, [location.search, defaultLens]);

  // Global Escape key returns to Lenses grid if inside a lens
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        if (activeLens !== null) {
          // If we are focused on a country or path on globe, clear focus first
          if (focusCountry || focusPath) {
            setFocusCountry(null);
            setFocusCoords(null);
            setFocusPath(null);
            return;
          }
          // Otherwise, return to 2x2 grid
          setActiveLens(null);
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [activeLens, focusCountry, focusPath]);

  // Pre-fetch CVE feed timestamp so it is immediately ready when opening Neural Port
  useEffect(() => {
    fetch('/cve-feed.json', { cache: 'no-store' })
      .then(res => res.ok ? res.json() : null)
      .then(d => {
        if (d && d.last_sync) {
          const parts = d.last_sync.split(' ');
          if (parts[0] && parts[0].includes('-')) {
            const ymd = parts[0].split('-');
            if (ymd.length === 3) parts[0] = ymd[2] + '-' + ymd[1] + '-' + ymd[0];
          }
          setCveSync(parts.join(' '));
        }
      })
      .catch(() => {});
  }, []);

  // Telemetry Fetching (Cloudflare Edge Worker)
  useEffect(() => {
    const REMOTE_API = 'https://bugterium-security-monitor.bugterium.workers.dev';
    const FETCH_TIMEOUT_MS = 6000;
    let isMounted = true;

    const fetchData = async () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        let response = null;
        if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
          try {
            const localCtrl = new AbortController();
            const localTimer = setTimeout(() => localCtrl.abort(), 1200);
            const localProto = window.location.protocol === 'https:' ? 'https:' : 'http:';
            // nosemgrep: typescript.react.security.react-insecure-request.react-insecure-request
            const localRes = await fetch(`${localProto}//127.0.0.1:8787`, { signal: localCtrl.signal });
            clearTimeout(localTimer);
            if (localRes.ok) response = localRes;
          } catch {
            // Local worker not running, fallback to remote
          }
        }
        if (!response) {
          response = await fetch(REMOTE_API, { signal: controller.signal });
        }
        const result = await response.json();
        if (!isMounted) return;
        if (response.ok && result.status === 'ok') {
          setData(result);
          setErrorMsg(null);
          setIsLive(true);
          const iso = result.meta && result.meta.generated_at ? result.meta.generated_at : new Date().toISOString();
          const gmt4 = new Date(new Date(iso).getTime() + (4 * 60 * 60 * 1000));
          setTelemetrySync(gmt4.toISOString().replace('T', ' ').substring(0, 16) + ' GMT+4');
        } else {
          setErrorMsg('WAITING FOR SNAPSHOT (CODE: ' + (result.code || response.status) + ')...');
          setIsLive(false);
          const nowGmt4 = new Date(Date.now() + (4 * 60 * 60 * 1000));
          setTelemetrySync(nowGmt4.toISOString().replace('T', ' ').substring(0, 16) + ' GMT+4');
        }
      } catch {
        if (!isMounted) return;
        setIsLive(false);
        setErrorMsg('OFFLINE MODE (FALLBACK TELEMETRY)');
        const nowGmt4 = new Date(Date.now() + (4 * 60 * 60 * 1000));
        setTelemetrySync(nowGmt4.toISOString().replace('T', ' ').substring(0, 16) + ' GMT+4');
      } finally {
        clearTimeout(timer);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000);
    const onVisibility = () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'visible') fetchData();
    };
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisibility);

    return () => {
      isMounted = false;
      clearInterval(interval);
      if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  // Scrambler animation for CVE feed sync (Neural Port)
  useEffect(() => {
    if (activeLens !== 'neural-port' || !cveSync) return;
    setIsCveAnimating(true);
    setIsTextReady(false);
    const target = cveSync;
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*';
    let frame = 0;
    const interval = setInterval(() => {
      frame += 0.25;
      const revealed = target.slice(0, Math.floor(frame));
      const scrambled = target.slice(Math.floor(frame)).split('').map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
      setDisplayCveSync(revealed + scrambled);
      if (frame >= target.length) {
        clearInterval(interval);
        setDisplayCveSync(target);
        setIsCveAnimating(false);
        setIsTextReady(true);
      }
    }, 35);
    return () => clearInterval(interval);
  }, [cveSync, activeLens, lensMountKey]);

  // Scrambler animation for Cloudflare Telemetry sync (Globe, Hub)
  useEffect(() => {
    if (!telemetrySync) return;
    setIsTelemetryAnimating(true);
    const target = telemetrySync;
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*';
    let frame = 0;
    const interval = setInterval(() => {
      frame += 0.35;
      const revealed = target.slice(0, Math.floor(frame));
      const scrambled = target.slice(Math.floor(frame)).split('').map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
      setDisplayTelemetrySync(revealed + scrambled);
      if (frame >= target.length) {
        clearInterval(interval);
        setDisplayTelemetrySync(target);
        setIsTelemetryAnimating(false);
      }
    }, 30);
    return () => clearInterval(interval);
  }, [telemetrySync]);

  const { security_metrics, geo_data, attacks_by_country, timeline, path_data, user_agent_data, status_breakdown } = data;

  const renderBreakdown = (prefix, color) => {
    if (!status_breakdown) return null;
    const filtered = status_breakdown.filter(s => s.code >= prefix * 100 && s.code < (prefix + 1) * 100).sort((a, b) => a.code - b.code);
    if (filtered.length === 0) return <div style={{ fontSize: '10px', color: '#6a6a6a', marginTop: '5px' }}>No errors</div>;
    const get5xxOriginTag = (code) => {
      if (prefix !== 5) return null;
      const isPlatform = code === 502 || code === 503 || code === 504;
      return {
        tag: isPlatform ? '[PLAT]' : '[APP]',
        title: isPlatform
          ? 'Platform / Cloudflare Edge error (cache=miss, origin=0)'
          : 'Application / Origin Worker error',
      };
    };
    return (
      <div style={{ display: 'grid', gridAutoFlow: 'column', gridTemplateRows: 'repeat(' + Math.ceil(filtered.length / 2) + ', auto)', gap: '4px 15px', marginTop: '5px' }}>
        {filtered.map(s => {
          const originTag = s.count > 0 ? get5xxOriginTag(s.code) : null;
          return (
            <div key={s.code} title={originTag ? originTag.title : undefined} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: color, borderBottom: '1px solid #222', paddingBottom: '2px', paddingLeft: '4px', paddingRight: '4px' }}>
              <span>
                {s.code}
                {originTag && (
                  <span style={{ fontSize: '8px', color: '#6a6a6a', marginLeft: '4px' }}>{originTag.tag}</span>
                )}
              </span>
              <span>{s.count}</span>
            </div>
          );
        })}
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

  const SPECIAL_SOURCE_TAGS = {
    T1: '[TOR]',
    XX: '[UNKNOWN]',
  };

  const getSpecialSourceTag = (code) => {
    if (!code) return null;
    if (SPECIAL_SOURCE_TAGS[code]) return SPECIAL_SOURCE_TAGS[code];
    const coords = countryCoords[code];
    return Array.isArray(coords) && coords.length >= 2 ? null : '[NO GEO]';
  };

  const resolveFocusCoords = (code) => {
    if (!code || code === 'XX' || code === 'T1') return null;
    const coords = countryCoords[code];
    if (!Array.isArray(coords) || coords.length < 2) return null;
    return { lat: coords[0], lng: coords[1] };
  };

  const handleCountrySelect = (country) => {
    if (focusCountry === country) {
      setFocusCountry(null);
      setFocusCoords(null);
    } else {
      setFocusCountry(country);
      setFocusCoords(resolveFocusCoords(country));
    }
    setFocusPath(null);
  };

  const specialSources = filteredCountries.filter(item => getSpecialSourceTag(item.country) !== null);

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
    <div className={styles.layout}>
      
      {/* ======================================================== */}
      {/* 1. ЛЕВАЯ КОЛОНКА (Сетка всегда фиксирована на 320px)       */}
      {/* ======================================================== */}
      <div className={styles.leftCol}>
        
        {/* А. Состояние: Lenses Hub (Главная сетка 2x2) */}
        {activeLens === null && (
          <>
            <Link to="/reference" className={styles.card}>
              <div className={styles.cardLabel}>REFERENCE</div>
              <div className={styles.cardDesc}>Applications / AI / Cloud / Infrastructure / Networks / Virtualization / Information Security / OSINT / Anonymity & OpSec</div>
            </Link>
            <Link to="/writeups" className={styles.card}>
              <div className={styles.cardLabel}>WRITEUPS</div>
              <div className={styles.cardDesc}>Hack The Box / All Machines / Season 12 / OSCP (Linux, Windows, Active Directory and Networks) / Pro Labs</div>
            </Link>
          </>
        )}

        {/* Б. Состояние: Security Globe */}
        {activeLens === 'globe' && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel} style={{ fontSize: "16px" }}>REQUESTS (24H) <span style={{ fontSize: '10px', color: '#666', fontWeight: 'normal', marginLeft: '4px' }}>[WORKERS]</span></div>
              <div className={styles.cardDesc} style={{ fontSize: "28px", color: "#ff8c00", marginTop: "10px", fontWeight: "bold" }}>{security_metrics.worker_requests_24h}</div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardLabel}>CLIENT ERRORS <span style={{ fontSize: '10px', color: '#666', fontWeight: 'normal', marginLeft: '4px' }}>[HTTP]</span></div>
              <div className={styles.cardDesc} style={{ fontSize: '28px', color: security_metrics.client_errors_4xx > 0 ? '#ff8c00' : '#fff', marginTop: '10px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px', paddingLeft: '4px' }}>{security_metrics.client_errors_4xx || 0}</div>
              <div style={{ marginTop: '10px' }}>{renderBreakdown(4, '#ff8c00')}</div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardLabel}>SERVER ERRORS <span style={{ fontSize: '10px', color: '#666', fontWeight: 'normal', marginLeft: '4px' }}>[HTTP]</span></div>
              <div className={styles.cardDesc} style={{ fontSize: '28px', color: security_metrics.server_errors_5xx > 0 ? '#ff8c00' : '#fff', marginTop: '10px', fontWeight: 'bold', borderBottom: '1px solid #222', paddingBottom: '10px', paddingLeft: '4px' }}>{security_metrics.server_errors_5xx || 0}</div>
              <div style={{ marginTop: '10px' }}>{renderBreakdown(5, '#ff8c00')}</div>
            </div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
              <div className={styles.card} style={{ flex: 1, minWidth: 0, textAlign: 'center' }}>
                <div className={styles.cardLabel} style={{ fontSize: '12px', letterSpacing: '0.05em', margin: 0 }}>LEGITIMATE <span style={{ fontSize: '9px', color: '#666', fontWeight: 'normal' }}>[HEURISTIC]</span></div>
                <div className={styles.cardDesc} style={{ fontSize: '28px', color: '#ff8c00', marginTop: '4px', fontWeight: 'bold' }}>[ {security_metrics.health_percent || '100.0'}% ]</div>
              </div>
              <div className={styles.card} style={{ flex: 1, minWidth: 0, textAlign: 'center' }}>
                <div className={styles.cardLabel} style={{ fontSize: '12px', letterSpacing: '0.05em', margin: 0 }}>SUSPICIOUS <span style={{ fontSize: '9px', color: '#666', fontWeight: 'normal' }}>[HEURISTIC]</span></div>
                <div className={styles.cardDesc} style={{ fontSize: '28px', color: '#ff8c00', marginTop: '4px', fontWeight: 'bold' }}>[ {(100 - parseFloat(security_metrics.health_percent || '100.0')).toFixed(1)}% ]</div>
              </div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardLabel} style={{ fontSize: '12px' }}>
                PROBE VECTORS <span style={{ fontSize: '9px', color: '#666', fontWeight: 'normal' }}>[CLASSIFIER]</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '10px' }}>
                {[
                  { label: 'SECRET LEAKS (.env, .git)', count: path_data.attacks ? path_data.attacks.filter(p => getPathFamily(p.path).name === 'SECRET LEAK').reduce((a, b) => a + b.count, 0) : 0, color: '#c00030' },
                  { label: 'CMS & WORDPRESS', count: path_data.attacks ? path_data.attacks.filter(p => getPathFamily(p.path).name === 'WORDPRESS PROBE').reduce((a, b) => a + b.count, 0) : 0, color: '#ff8c00' },
                  { label: 'API EXPOSURE', count: path_data.attacks ? path_data.attacks.filter(p => getPathFamily(p.path).name === 'API EXPOSURE').reduce((a, b) => a + b.count, 0) : 0, color: '#a855f7' },
                  { label: 'DATABASE PROBES', count: path_data.attacks ? path_data.attacks.filter(p => getPathFamily(p.path).name === 'DATABASE PROBE').reduce((a, b) => a + b.count, 0) : 0, color: '#a855f7' }
                ].map(v => (
                  <div key={v.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                    <span style={{ color: v.color }}>{v.label}</span>
                    <span style={{ color: '#ffffff', fontWeight: 'bold' }}>{v.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* В. Состояние: Neural Port */}
        {activeLens === 'neural-port' && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel}>KNOWLEDGE TAXONOMY</div>
              <div className={styles.cardDesc} style={{ color: '#888888', marginTop: '8px', lineHeight: '1.5' }}>
                Organized repository of security intelligence, HTB walkthroughs, defensive configurations, CVEs, and MITRE adversary mapping.
              </div>
            </div>
            <Link to="/writeups" className={styles.card}>
              <div className={styles.cardLabel}>WRITEUPS DIRECTORY ↗</div>
              <div className={styles.cardDesc}>Hack The Box Machines, Seasons, and Pro Labs documentation.</div>
            </Link>
            <Link to="/reference" className={styles.card}>
              <div className={styles.cardLabel}>REFERENCE ARCHIVES ↗</div>
              <div className={styles.cardDesc}>Cloud, AI, Network security, and operational defense manuals.</div>
            </Link>
          </>
        )}

        {/* Г. Состояние: ATT&CK Matrix */}
        {activeLens === 'attack-matrix' && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel}>MITRE ATT&CK SCOPE</div>
              <div className={styles.cardDesc} style={{ color: '#888888', marginTop: '8px', lineHeight: '1.5' }}>
                Enterprise matrix mapping real-world adversary tactics and techniques against active edge defenses.
              </div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardLabel}>TACTICAL PHASES</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px', fontSize: '11px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>INITIAL ACCESS</span>
                  <span style={{ color: '#00ff66', fontWeight: 'bold' }}>4 COVERED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>EXECUTION</span>
                  <span style={{ color: '#00ff66', fontWeight: 'bold' }}>3 COVERED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>CREDENTIAL ACCESS</span>
                  <span style={{ color: '#00ff66', fontWeight: 'bold' }}>4 COVERED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>DISCOVERY</span>
                  <span style={{ color: '#00ff66', fontWeight: 'bold' }}>3 COVERED</span>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Д. Состояние: Assurance */}
        {activeLens === 'assurance' && (
          <>
            <div className={styles.card}>
              <div className={styles.cardLabel}>DEFENSE ASSURANCE</div>
              <div className={styles.cardDesc} style={{ color: '#888888', marginTop: '8px', lineHeight: '1.5' }}>
                Continuous automated audit of Zero Trust enforcement, WAF isolation, cryptographic signing, and supply chain security.
              </div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardLabel}>ASSURANCE SUMMARY</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px', fontSize: '11px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>CONTROLS EVALUATED</span>
                  <span style={{ color: '#ffffff', fontWeight: 'bold' }}>6 CONTROLS</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>COMPLIANCE STATUS</span>
                  <span style={{ color: '#00ff66', fontWeight: 'bold' }}>100% VERIFIED</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#888888' }}>ZERO-COST CONSTRAINT</span>
                  <span style={{ color: '#0055ff', fontWeight: 'bold' }}>$0.00 / FREE TIER</span>
                </div>
              </div>
            </div>
          </>
        )}

      </div>

      {/* ======================================================== */}
      {/* 2. ЦЕНТРАЛЬНЫЙ ПОРТ (STAGE & HUD)                          */}
      {/* ======================================================== */}
      <div className={styles.centerCol}>
        <div 
          className="app" 
          style={{ 
            position: 'relative', 
            width: '100%', 
            height: '100%', 
            zIndex: 1, 
            display: 'grid', 
            gridTemplateRows: activeLens === 'neural-port' ? '1fr' : '40px 1fr' 
          }}
        >
          
          {/* ВЕРХНИЙ ХЕДЕР HUD (Скрыт для Neural Port, так как Neural Port имеет собственный встроенный HUD) */}
          {activeLens !== 'neural-port' && (
            <header className="hud">
              <span className="brand">
                <span 
                  className="brand-prefix"
                  onClick={() => setActiveLens(null)}
                  style={{ cursor: 'pointer' }}
                  title="Return to Lenses Hub"
                >
                  BUGTERIUM
                </span>
                <span className="sep">/</span> 
                {activeLens === null ? (
                  'LENSES'
                ) : (
                  <button
                    type="button"
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'inherit',
                      font: 'inherit',
                      letterSpacing: 'inherit',
                      textTransform: 'inherit',
                      cursor: 'pointer',
                      padding: 0
                    }}
                    onClick={() => setActiveLens(null)}
                    title="Return to Lenses Hub"
                  >
                    LENSES
                  </button>
                )}
              </span>

              <nav className="crumbs">
                {activeLens === 'globe' && (
                  <>
                    <span className="crumb-item">
                      <span className="crumb" style={{ cursor: 'default', pointerEvents: 'none' }}>
                        GLOBE
                      </span>
                    </span>
                    <span className="sep">/</span>
                    {!focusCountry && !focusPath ? (
                      <span className="crumb-item">
                        <span className="crumb active">WORLD</span>
                      </span>
                    ) : (
                      <>
                        <span className="crumb-item">
                          <button
                            type="button"
                            className="crumb"
                            onClick={() => { setFocusCountry(null); setFocusCoords(null); setFocusPath(null); }}
                            title="Reset view to World"
                          >
                            WORLD
                          </button>
                        </span>
                        <span className="sep">/</span>
                        <span className="crumb-item">
                          <span className="crumb active">
                            {focusCountry ? `FOCUS: [ ${focusCountry} ]` : `FOCUS: [ ${focusPath} ]`}
                          </span>
                        </span>
                      </>
                    )}
                  </>
                )}
                {activeLens === 'attack-matrix' && (
                  <>
                    <span className="crumb-item">
                      <span className="crumb" style={{ cursor: 'default', pointerEvents: 'none' }}>
                        ATT&CK MATRIX
                      </span>
                    </span>
                    <span className="sep">/</span>
                    <span className="crumb-item">
                      <span className="crumb active">ENTERPRISE</span>
                    </span>
                  </>
                )}
                {activeLens === 'assurance' && (
                  <>
                    <span className="crumb-item">
                      <span className="crumb" style={{ cursor: 'default', pointerEvents: 'none' }}>
                        ASSURANCE
                      </span>
                    </span>
                    <span className="sep">/</span>
                    <span className="crumb-item">
                      <span className="crumb active">CONTROLS</span>
                    </span>
                  </>
                )}
              </nav>

              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <span className="status">
                  {activeLens === null && '4 LENSES ONLINE'}
                  {activeLens === 'globe' && `${security_metrics.worker_requests_24h} REQUESTS / ${security_metrics.blocked_403} BLOCKED`}
                  {activeLens === 'attack-matrix' && '14 TECHNIQUES / 4 TACTICS'}
                  {activeLens === 'assurance' && '6 CONTROLS VERIFIED'}
                </span>
              </div>
            </header>
          )}

          {/* ОСНОВНОЙ ВЬЮПОРТ (STAGE) */}
          <main className="stage" style={{ position: 'relative', width: '100%', height: '100%', overflow: 'hidden' }}>
            
            {/* А. Сетка 2x2 Lenses Hub (когда activeLens === null) */}
            {activeLens === null && (
              <LensesHub onSelectLens={setActiveLens} metrics={security_metrics} />
            )}

            {/* Б. Security Globe */}
            {activeLens === 'globe' && (
              <>
                {/* Легенда глобуса */}
                <div style={{ position: 'absolute', top: '16px', left: '16px', zIndex: 10, display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: '#888888', userSelect: 'none' }}>
                  {[
                    { key: 'threats', label: 'Events', color: '#ff8c00' },
                    { key: 'shield', label: 'Defense In Depth', color: '#0000ff' },
                    { key: 'timeline', label: '24H Traffic Timeline', color: '#a855f7' }
                  ].map(item => (
                    <div key={item.key} style={legendItemStyle(layers[item.key])} onClick={() => toggleLayer(item.key)}>
                      <svg width="8" height="8" style={{ marginRight: '6px', flexShrink: 0 }}>
                        <circle cx="4" cy="4" r="4" fill={layers[item.key] ? item.color : '#6a6a6a'} />
                      </svg>
                      <span style={{ lineHeight: 1, transform: 'translateY(1px)' }}>{item.label}</span>
                    </div>
                  ))}
                </div>

                <div style={{ position: 'absolute', bottom: '16px', left: '16px', zIndex: 10, fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', letterSpacing: '0.05em', color: '#c00030', pointerEvents: 'none', lineHeight: '1.5' }}>
                  <div>Aggregated real-world traffic data.</div>
                  <div>No PII or IP addresses collected.</div>
                  <div>Fully anonymized.</div>
                </div>

                <BrowserOnly fallback={<div style={{ background: '#000', height: '100%' }} />}>
                  {() => (
                    <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#c00030', fontFamily: 'JetBrains Mono, monospace' }}>INITIALIZING GLOBE...</div>}>
                      <SecurityGlobe 
                        geoData={displayGeoData}
                        attacksData={attacks_by_country}
                        focusCoords={focusCoords} 
                        focusCountry={focusCountry} 
                        metrics={security_metrics} 
                        timeline={timeline} 
                        layers={layers} 
                        focusPath={focusPath}
                        viewMode={viewMode}
                        onCountryClick={handleCountrySelect} 
                      />
                    </Suspense>
                  )}
                </BrowserOnly>
              </>
            )}

            {/* В. Neural Port */}
            {activeLens === 'neural-port' && (
              <BrowserOnly fallback={<div style={{ background: '#000', height: '100%' }} />}>
                {() => (
                  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#c00030', fontFamily: 'JetBrains Mono, monospace' }}>INITIALIZING NEURAL PORT...</div>}>
                    <NeuralGraph 
                      key={'neural-graph-' + lensMountKey}
                      embedded={true} 
                      onBackToLenses={() => setActiveLens(null)} 
                      onReady={() => setIsGraphReady(true)} 
                    />
                  </Suspense>
                )}
              </BrowserOnly>
            )}

            {/* Г. ATT&CK Matrix */}
            {activeLens === 'attack-matrix' && (
              <BrowserOnly fallback={<div style={{ background: '#000', height: '100%' }} />}>
                {() => (
                  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#00ff66', fontFamily: 'JetBrains Mono, monospace' }}>INITIALIZING ATT&CK MATRIX...</div>}>
                    <AttackMatrix />
                  </Suspense>
                )}
              </BrowserOnly>
            )}

            {/* Д. Assurance View */}
            {activeLens === 'assurance' && (
              <BrowserOnly fallback={<div style={{ background: '#000', height: '100%' }} />}>
                {() => (
                  <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: '#0055ff', fontFamily: 'JetBrains Mono, monospace' }}>INITIALIZING ASSURANCE...</div>}>
                    <AssuranceView />
                  </Suspense>
                )}
              </BrowserOnly>
            )}

          </main>
        </div>
      </div>

      {/* ======================================================== */}
      {/* 3. ПРАВАЯ КОЛОНКА (Сетка всегда фиксирована на 320px)      */}
      {/* ======================================================== */}
      <div className={styles.rightCol}>
        
        {/* А. Состояние: Lenses Hub (Резервная тактическая рамка) */}
        {activeLens === null && (
          <>
            <div className={styles.threatsHeader}>SYSTEM TELEMETRY</div>
            <div style={{ padding: '14px', border: '1px solid #1a1a1a', background: '#0a0a0a', fontSize: '11px', color: '#6a6a6a', fontFamily: 'JetBrains Mono, monospace', lineHeight: '1.6' }}>
              <div style={{ color: '#d7d7d7', fontWeight: 'bold', marginBottom: '8px' }}>TACTICAL LENSES HUB</div>
              <div>Select an operational lens in the central port to engage full-spectrum telemetry.</div>
              <div style={{ marginTop: '14px', display: 'flex', justifyContent: 'space-between', borderTop: '1px solid #1a1a1a', paddingTop: '8px' }}>
                <span style={{ color: '#888888' }}>RADAR STATUS</span>
                <span style={{ color: '#c00030', fontWeight: 'bold' }}>READY // ONLINE</span>
              </div>
            </div>
          </>
        )}

        {/* Б. Состояние: Neural Port (Живой фид CVE) */}
        {activeLens === 'neural-port' && (
          <>
            <div className={styles.threatsHeader}>LIVE THREATS</div>
            <LiveThreats onSync={setCveSync} />
          </>
        )}

        {/* В. Состояние: Security Globe (Top Sources, кнопки линз УДАЛЕНЫ) */}
        {activeLens === 'globe' && (
          <div>
            <div className={styles.threatsHeader}>
              TOP SOURCES <span style={{ fontSize: '10px', color: '#666', fontWeight: 'normal' }}>[HTTP]</span>
            </div>

            <div style={{ marginBottom: '14px', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '6px' }}>MODE:</div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <button 
                  type="button"
                  style={{
                    background: 'none', border: 'none', padding: 0,
                    fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', cursor: 'pointer',
                    color: viewMode === 'traffic' ? '#c00030' : '#666',
                    fontWeight: viewMode === 'traffic' ? 'bold' : 'normal'
                  }}
                  onClick={() => { setViewMode('traffic'); setFocusPath(null); setFocusCountry(null); setFocusCoords(null); }}
                >
                  [ ALL TRAFFIC ]
                </button>
                <button 
                  type="button"
                  style={{
                    background: 'none', border: 'none', padding: 0,
                    fontFamily: 'JetBrains Mono, monospace', fontSize: '11px', cursor: 'pointer',
                    color: viewMode === 'attacks' ? '#c00030' : '#666',
                    fontWeight: viewMode === 'attacks' ? 'bold' : 'normal'
                  }}
                  onClick={() => { setViewMode('attacks'); setFocusPath(null); setFocusCountry(null); setFocusCoords(null); }}
                >
                  [ SUSPICIOUS ACTIVITY ]
                </button>
              </div>
            </div>

            <div style={{ marginBottom: '14px', borderBottom: '1px solid #222', paddingBottom: '10px' }}>
              <div style={{ fontSize: '10px', color: '#666', marginBottom: '6px' }}>FILTER BY:</div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button type="button" style={tabButtonStyle('countries')} onClick={() => handleTabClick('countries')}>[ COUNTRIES ]</button>
                <button type="button" style={tabButtonStyle('paths')} onClick={() => handleTabClick('paths')}>[ PATHS ]</button>
                <button type="button" style={tabButtonStyle('agents')} onClick={() => handleTabClick('agents')}>[ USER AGENTS ]</button>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: 'calc(100vh - 350px)', overflowY: 'auto' }}>
              {activeTab === 'countries' && specialSources.length > 0 && (
                <div style={{
                  padding: '6px 10px',
                  border: '1px solid #1a1a1a',
                  backgroundColor: '#0a0a0a',
                  fontSize: '10px',
                  color: '#6a6a6a',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <span>SPECIAL SOURCES</span>
                  <span style={{ color: '#d7d7d7' }}>
                    {specialSources.map(s => `${s.country}:${s.count}`).join(' // ')}
                  </span>
                </div>
              )}
              {activeTab === 'countries' && filteredCountries.map(item => {
                const isFocused = focusCountry === item.country;
                const specialTag = getSpecialSourceTag(item.country);
                return (
                  <div 
                    key={item.country} 
                    className={styles.threatCard} 
                    style={{ 
                      cursor: 'pointer', 
                      borderColor: isFocused ? '#c00030' : undefined, 
                      backgroundColor: isFocused ? 'rgba(192, 0, 48, 0.12)' : undefined 
                    }} 
                    onClick={() => handleCountrySelect(item.country)}
                  >
                    <div className={styles.threatHeader}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <div className={styles.threatId}>{item.country}</div>
                        {specialTag && (
                          <span style={{ fontSize: '9px', color: '#6a6a6a', border: '1px solid #1a1a1a', padding: '1px 4px' }}>
                            {specialTag}
                          </span>
                        )}
                      </div>
                      <div className={styles.threatRight}>
                        <div className={styles.threatCvss}>{item.count}</div>
                      </div>
                    </div>
                  </div>
                );
              })}

              {activeTab === 'paths' && filteredPaths.map(item => {
                const family = getPathFamily(item.path);
                const isFocused = focusPath === item.path;
                return (
                  <div 
                    key={item.path} 
                    className={styles.threatCard} 
                    style={{ 
                      cursor: 'pointer', 
                      borderColor: isFocused ? '#c00030' : undefined, 
                      backgroundColor: isFocused ? 'rgba(192, 0, 48, 0.12)' : undefined,
                      padding: '10px 12px'
                    }} 
                    onClick={() => handlePathClick(item.path)}
                  >
                    <div className={styles.threatHeader} style={{ marginBottom: isFocused ? '6px' : '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0, flex: 1 }}>
                        <span style={{ 
                          fontSize: '9px', 
                          padding: '1px 5px', 
                          letterSpacing: '0.05em', 
                          fontWeight: '600', 
                          color: family.color, 
                          border: `1px solid ${family.color}`,
                          background: 'rgba(0,0,0,0.5)',
                          whiteSpace: 'nowrap'
                        }}>
                          {family.name}
                        </span>
                        <div className={styles.threatId} style={{ fontSize: '11px', wordBreak: 'break-all', color: isFocused ? '#fff' : undefined }}>
                          {item.path}
                        </div>
                      </div>
                      <div className={styles.threatRight}>
                        <div className={styles.threatCvss}>{item.count}</div>
                      </div>
                    </div>
                  </div>
                );
              })}

              {activeTab === 'agents' && filteredAgents.slice(0, 10).map((item, idx) => {
                const cat = getUaCategory(item.ua);
                return (
                  <div key={idx} className={styles.threatCard} title={item.ua} style={{ padding: '8px 12px' }}>
                    <div className={styles.threatHeader} style={{ marginBottom: '2px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0, flex: 1 }}>
                        <span style={{ 
                          fontSize: '9px', 
                          padding: '1px 5px', 
                          letterSpacing: '0.05em', 
                          fontWeight: '600', 
                          color: cat.color, 
                          border: `1px solid ${cat.color}`,
                          background: 'rgba(0,0,0,0.5)',
                          whiteSpace: 'nowrap'
                        }}>
                          {cat.name}
                        </span>
                        <div className={styles.threatId} style={{ fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                          {item.ua}
                        </div>
                      </div>
                      <div className={styles.threatRight}>
                        <div className={styles.threatCvss}>{item.count}</div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Г. Состояние: ATT&CK Matrix */}
        {activeLens === 'attack-matrix' && (
          <div>
            <div className={styles.threatsHeader}>COVERAGE METRICS</div>
            <div style={{ padding: '14px', border: '1px solid #1a1a1a', background: '#0a0a0a', fontSize: '11px', color: '#6a6a6a', fontFamily: 'JetBrains Mono, monospace', lineHeight: '1.6' }}>
              <div style={{ color: '#00ff66', fontWeight: 'bold', marginBottom: '8px' }}>MITRE ATT&CK TELEMETRY</div>
              <div>Active defensive mapping against enterprise adversary tactics.</div>
              <div style={{ marginTop: '12px', borderTop: '1px solid #1a1a1a', paddingTop: '8px' }}>
                <span style={{ color: '#888888' }}>DETECTION ENGINE: </span>
                <span style={{ color: '#ffffff' }}>PASSIVE WAF RULES</span>
              </div>
            </div>
          </div>
        )}

        {/* Д. Состояние: Assurance */}
        {activeLens === 'assurance' && (
          <div>
            <div className={styles.threatsHeader}>ASSURANCE LOG</div>
            <div style={{ padding: '14px', border: '1px solid #1a1a1a', background: '#0a0a0a', fontSize: '11px', color: '#6a6a6a', fontFamily: 'JetBrains Mono, monospace', lineHeight: '1.6' }}>
              <div style={{ color: '#0055ff', fontWeight: 'bold', marginBottom: '8px' }}>CONTINUOUS AUDIT LOG</div>
              <div>6 of 6 security posture controls passing automated integrity checks.</div>
              <div style={{ marginTop: '12px', borderTop: '1px solid #1a1a1a', paddingTop: '8px' }}>
                <span style={{ color: '#888888' }}>LAST AUDIT: </span>
                <span style={{ color: '#00ff66' }}>PASSED GREEN</span>
              </div>
            </div>
          </div>
        )}

      </div>

      {/* ======================================================== */}
      {/* 4. ФУТЕРЫ (Нижняя строка сетки)                           */}
      {/* ======================================================== */}
      <div className={styles.leftFooter} style={{ display: 'flex', alignItems: 'center' }}>
        <svg width='14' height='14' viewBox='0 0 14 14' style={{ marginRight: '8px', transform: 'translateY(-0.5px)' }}>
          <circle cx='7' cy='7' r='5' fill='none' stroke='currentColor' strokeWidth='1' />
          {((activeLens === 'neural-port' ? (isGraphReady && isTextReady) : isLive)) && (
            <circle cx='7' cy='7' r='2.5' fill='#c00030' />
          )}
        </svg>
        SYSTEM READY
      </div>
      
      <div className={styles.centerFooter}>
        {activeLens === null 
          ? 'SELECT AN OPERATIONAL LENS TO ENGAGE · ESC TO CLEAR' 
          : 'PRESS ESC TO RETURN TO LENSES · CLICK TO INSPECT'}
      </div>
      
      <div className={styles.rightFooter} style={{ display: 'block', textAlign: 'center', width: '100%', padding: '10px 0' }}>
        <span style={{ display: 'inline-block', position: 'relative', transform: 'translateX(-6px)', whiteSpace: 'nowrap' }}>
          <span style={{ visibility: 'hidden', fontWeight: 'bold' }}>
            <span>{activeLens === 'neural-port' ? 'LAST SYNC:' : (isLive ? 'LIVE SYNC:' : 'LAST SYNC:')}</span> 0000-00-00 00:00 GMT+4
          </span>
          <span style={{ position: 'absolute', left: 0, top: 0 }}>
            <span className={activeLens === 'neural-port' ? (isCveAnimating ? styles.blink : '') : (isTelemetryAnimating ? styles.blink : '')} style={{ color: '#c00030', fontWeight: 'bold', transition: 'opacity 0.5s ease-out' }}>
              {activeLens === 'neural-port' ? 'LAST SYNC:' : (isLive ? 'LIVE SYNC:' : 'LAST SYNC:')}
            </span> {activeLens === 'neural-port' ? displayCveSync : displayTelemetrySync}
          </span>
        </span>
      </div>

    </div>
  );
}
