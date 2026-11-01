import React, { useState, useEffect } from 'react';
import Layout from '@theme/Layout';
import BrowserOnly from '@docusaurus/BrowserOnly';
import Link from '@docusaurus/Link';
import LiveThreats from '@site/src/components/LiveThreats';
import styles from './index.module.css';

export default function Home() {
  const [lastSync, setLastSync] = useState('0000-00-00 00:00 GMT+4'); 
  const [displaySync, setDisplaySync] = useState('0000-00-00 00:00 GMT+4');
  const [isAnimating, setIsAnimating] = useState(false);
  
  const [isGraphReady, setIsGraphReady] = useState(false);
  const [isTextReady, setIsTextReady] = useState(false);

  useEffect(() => {
    setIsAnimating(true);
    setIsTextReady(false); 

    const target = lastSync;
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*';
    let frame = 0;

    const interval = setInterval(() => {
      frame += 0.25; 
      const revealed = target.slice(0, Math.floor(frame));
      const scrambled = target.slice(Math.floor(frame)).split('').map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
      setDisplaySync(revealed + scrambled);
    }, 50); 

    return () => {
      clearInterval(interval);
    };
  }, [lastSync]);
  useEffect(() => {
    if (isGraphReady) {
      setDisplaySync(lastSync);
      setIsAnimating(false);
      setIsTextReady(true);
    }
  }, [isGraphReady, lastSync]);

  return (
    <Layout title="MethodMan / NEURAL PORT" description="Neural graph of MethodMan pentest walkthroughs" noFooter={true}>
      <div className={styles.layout}>

        <div className={styles.leftCol}>
          <Link to="/reference" className={styles.card}>
            <div className={styles.cardLabel}>REFERENCE</div>
            <div className={styles.cardDesc}>Applications / AI / Cloud / Infrastructure / Networks / Virtualization / Information Security / OSINT / Anonymity & OpSec</div>
          </Link>
          <Link to="/writeups" className={styles.card}>
            <div className={styles.cardLabel}>WRITEUPS</div>
            <div className={styles.cardDesc}>Hack The Box / All Machines / Season 12 / OSCP (Linux, Windows, Active Directory and Networks) / Pro Labs</div>
          </Link>
        </div>

        <div className={styles.centerCol}>
          <BrowserOnly fallback={<div style={{background:'var(--bg)',height:'100%'}} />}>
            {() => {
              const NeuralGraph = require('@site/src/components/NeuralGraph').default;
              return <NeuralGraph onReady={() => setIsGraphReady(true)} />;
            }}
          </BrowserOnly>
        </div>

        <div className={styles.rightCol}>
          <div className={styles.threatsHeader}>LIVE THREATS</div>
          <LiveThreats onSync={setLastSync} />
        </div>

        <div className={styles.leftFooter} style={{ display: 'flex', alignItems: 'center' }}>
          <svg width='14' height='14' viewBox='0 0 14 14' style={{ marginRight: '8px', transform: 'translateY(-0.5px)' }}>
            <circle cx='7' cy='7' r='5' fill='none' stroke='currentColor' strokeWidth='1' />
            {isGraphReady && isTextReady && (
              <circle cx='7' cy='7' r='2.5' fill='#c00030' />
            )}
          </svg>
          SYSTEM READY
        </div>
        
        <div className={styles.centerFooter}>PRESS ESC TO GO UP · CLICK TO DRILL IN OR VISIT</div>
        
        <div className={styles.rightFooter} style={{ display: 'block', textAlign: 'center', width: '100%', padding: '10px 0' }}>
          <span style={{ display: 'inline-block', position: 'relative', transform: 'translateX(-6px)', whiteSpace: 'nowrap' }}>
            
            <span style={{ visibility: 'hidden', fontWeight: 'bold' }}>
              <span>LAST SYNC:</span> 0000-00-00 00:00 GMT+4
            </span>

            <span style={{ position: 'absolute', left: 0, top: 0 }}>
              <span className={isAnimating ? styles.blink : ''} style={{ color: '#c00030', fontWeight: 'bold', transition: 'opacity 0.5s ease-out' }}>LAST SYNC:</span> {displaySync}
            </span>
            
          </span>
        </div>

      </div>
    </Layout>
  );
}