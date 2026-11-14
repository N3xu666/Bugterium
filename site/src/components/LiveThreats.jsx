import React, { useEffect, useState, useRef } from 'react';
import styles from '../pages/index.module.css';

function formatSyncTimestamp(raw) {
  if (!raw) return '';
  const parts = raw.split(' ');
  if (parts[0] && parts[0].includes('-')) {
    const ymd = parts[0].split('-');
    if (ymd.length === 3) parts[0] = ymd[2] + '-' + ymd[1] + '-' + ymd[0];
  }
  return parts.join(' ');
}

function LiveThreats({ onSync, feedData = null }) {
  const [threats, setThreats] = useState(() => (feedData?.cves ? feedData.cves : []));
  const [loading, setLoading] = useState(() => !(feedData && Array.isArray(feedData.cves)));
  const [error, setError] = useState(null);
  const hoverTimerRef = useRef(null);

  useEffect(() => {
    let isMounted = true;

    const applyFeed = (data) => {
      if (!isMounted || !data) return;
      setThreats(data.cves || []);
      if (onSync && data.last_sync) {
        onSync(formatSyncTimestamp(data.last_sync));
      }
      setLoading(false);
      setError(null);
    };

    const fetchData = () => {
      fetch('/cve-feed.json', { cache: 'no-store' })
        .then((res) => {
          if (!res.ok) throw new Error('Failed to fetch');
          return res.json();
        })
        .then(applyFeed)
        .catch((err) => {
          if (isMounted) {
            setError(err.message);
            setLoading(false);
          }
        });
    };

    if (feedData && Array.isArray(feedData.cves)) {
      applyFeed(feedData);
    } else {
      fetchData(); // Initial fetch only when parent has not pre-fetched feedData
    }

    // Auto-refresh every 10 minutes (600,000 ms)
    const intervalId = setInterval(fetchData, 600000);

    return () => {
      isMounted = false;
      clearInterval(intervalId);
      if (hoverTimerRef.current) {
        clearTimeout(hoverTimerRef.current);
        hoverTimerRef.current = null;
      }
    };
  }, [feedData, onSync]);

  if (loading) return <div className={styles.threatsPlaceholder}>Initializing feed...</div>;
  if (error) return <div className={styles.threatsPlaceholder}>Error: {error}</div>;
  if (!threats || !threats.length) return <div className={styles.threatsPlaceholder}>No active threats found.</div>;

  return (
    <div className={styles.threatList}>
      {threats.map((cve) => (
        <a
          key={cve.id}
          href={cve.url}
          target="_blank"
          rel="noopener noreferrer"
          className={styles.threatCard}
          onMouseEnter={() => {
            if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
            hoverTimerRef.current = setTimeout(() => {
              window.dispatchEvent(new CustomEvent('bugterium-focus-node', {
                detail: {
                  id: `cve:${cve.id}`,
                  label: cve.id,
                  cvss: cve.cvss,
                  epss: cve.epss,
                  description: cve.description,
                  url: cve.url
                }
              }));
            }, 150);
          }}
          onMouseLeave={() => {
            if (hoverTimerRef.current) {
              clearTimeout(hoverTimerRef.current);
              hoverTimerRef.current = null;
            }
          }}
        >
          <div className={styles.threatHeader}>
            <span className={styles.threatId}>{cve.id}</span>
            <div className={styles.threatRight}>
              <div className={styles.threatCvss}>
                <span>CVSS</span>
                <span>{cve.cvss.toFixed(1)}</span>
              </div>
            </div>
          </div>
          <div className={styles.threatDesc}>{cve.description}</div>
          <div className={styles.threatFooter}>
            <span className={styles.threatEpss}>EPSS {(cve.epss * 100).toFixed(1)}%</span>
            <div className={styles.threatNvd}>
              <span>NVD</span>
              <span className={styles.nvdArrow}>↗</span>
            </div>
          </div>
        </a>
      ))}
    </div>
  );
}

export default React.memo(LiveThreats);