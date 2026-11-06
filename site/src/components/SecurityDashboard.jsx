import React, { useState, useEffect } from 'react';
import styles from './SecurityDashboard.module.css';
import SecurityGlobe from './SecurityGlobe';

export default function SecurityDashboard() {
  const [data, setData] = useState(null);
  const [isLive, setIsLive] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('https://bugterium-security-monitor.bugterium.workers.dev');
        const result = await response.json();
        if (result.status === 'ok') {
          setData(result);
          setIsLive(true);
        }
      } catch (error) {
        setIsLive(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // Обновление каждые 10 сек
    return () => clearInterval(interval);
  }, []);

  if (!data) return <div className={styles.loading}>INITIALIZING SECURITY FEED...</div>;

  const { security_metrics, geo_data } = data;

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h2>SECURITY MONITOR</h2>
        <div className={styles.status}>
          <span className={isLive ? styles.dotLive : styles.dotOffline}></span>
          {isLive ? 'LIVE' : 'OFFLINE'}
        </div>
      </div>

      <div className={styles.mainGrid}>
        {/* Левая часть: Глобус */}
        <div className={styles.globeSection}>
          <SecurityGlobe geoData={geo_data} />
        </div>

        {/* Правая часть: Метрики и Список стран */}
        <div className={styles.sidebar}>
          <div className={styles.metricsGrid}>
            <div className={styles.card}>
              <div className={styles.cardTitle}>Requests (24h)</div>
              <div className={styles.cardValue}>{security_metrics.worker_requests_24h}</div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardTitle}>Errors</div>
              <div className={styles.cardValue} style={{ color: security_metrics.worker_errors_24h > 0 ? '#ff003c' : 'var(--ifm-color-success)' }}>
                {security_metrics.worker_errors_24h}
              </div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardTitle}>Blocked (403)</div>
              <div className={styles.cardValue} style={{ color: security_metrics.blocked_403 > 0 ? '#ff003c' : 'inherit' }}>
                {security_metrics.blocked_403}
              </div>
            </div>
            <div className={styles.card}>
              <div className={styles.cardTitle}>Rate Limited</div>
              <div className={styles.cardValue}>{security_metrics.blocked_429}</div>
            </div>
          </div>

          <div className={styles.countryList}>
            <h3>TOP SOURCES</h3>
            <div className={styles.listItems}>
              {geo_data.slice(0, 5).map((item, idx) => (
                <div key={idx} className={styles.listItem}>
                  <span>{item.country}</span>
                  <span className={styles.countBadge}>{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}