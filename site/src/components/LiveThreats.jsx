import React, { useEffect, useState } from 'react';
import styles from '../pages/index.module.css';

export default function LiveThreats({ onSync }) {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let isMounted = true;

    const fetchData = () => {
      fetch('/cve-feed.json', { cache: 'no-store' })
        .then((res) => {
          if (!res.ok) throw new Error('Failed to fetch');
          return res.json();
        })
        .then((data) => {
          if (isMounted) {
            setThreats(data.cves);
            if (onSync) {
              const parts = data.last_sync.split(' ');
              if (parts[0] && parts[0].includes('-')) {
                const ymd = parts[0].split('-');
                if (ymd.length === 3) parts[0] = ymd[2] + '-' + ymd[1] + '-' + ymd[0];
              }
              onSync(parts.join(' '));
            }
            setLoading(false);
            setError(null);
          }
        })
        .catch((err) => {
          if (isMounted) {
            setError(err.message);
            setLoading(false);
          }
        });
    };

    fetchData(); // Первая загрузка при монтировании
    
    // Автообновление каждые 10 минут (600 000 мс)
    const intervalId = setInterval(fetchData, 600000);

    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
  }, [onSync]);

  if (loading) return <div className={styles.threatsPlaceholder}>Initializing feed...</div>;
  if (error) return <div className={styles.threatsPlaceholder}>Error: {error}</div>;
  if (!threats || !threats.length) return <div className={styles.threatsPlaceholder}>No active threats found.</div>;

  return (
    <div className={styles.threatList}>
      {threats.map((cve) => (
        <a key={cve.id} href={cve.url} target="_blank" rel="noopener noreferrer" className={styles.threatCard}>
          <div className={styles.threatHeader}>
            <span className={styles.threatId}>{cve.id}</span>
            <div className={styles.threatRight}>
              <button
                type="button"
                className={styles.threatTargetBtn}
                title="Focus on 3D Neural Graph"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
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
                }}
              >
                [⌖ FOCUS]
              </button>
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