import React, { useEffect, useRef, useState, useMemo } from 'react';
import Globe from 'react-globe.gl';
import * as THREE from 'three';
import { countryCoords } from './countryCoords';

export default function SecurityGlobe({ geoData, focusCoords, focusCountry, metrics, layers, timeline, onCountryClick }) {
  const globeEl = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [globeMaterial, setGlobeMaterial] = useState(null);
  const [altitude, setAltitude] = useState(2.5);

  const timelineObjRef = useRef(null);

  useEffect(() => {
    const img = new Image();
    img.src = '/earth_8k.jpg';

    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const data = imgData.data;

      for (let i = 0; i < data.length; i += 4) {
        const r = data[i], g = data[i+1], b = data[i+2];
        if (b > r * 1.1) {
          data[i] = 0; data[i+1] = 0; data[i+2] = 0;
        } else {
          const brightness = (r + g + b) / (255 * 3);
          data[i] = Math.floor(179 * brightness);
          data[i+1] = 0;
          data[i+2] = Math.floor(40 * brightness);
        }
      }
      ctx.putImageData(imgData, 0, 0);

      const texture = new THREE.CanvasTexture(canvas);
      texture.colorSpace = THREE.SRGBColorSpace;
      texture.anisotropy = 16;
      texture.minFilter = THREE.LinearFilter;
      texture.magFilter = THREE.LinearFilter;

      const mat = new THREE.MeshBasicMaterial({ map: texture });
      setGlobeMaterial(mat);
    };
  }, []);

  // --- ЩИТ ---
  const createShield = (metricsData) => {
    const group = new THREE.Group();
    if (!metricsData) return group;
    const createGlow = (color, opacity) => {
      const mat = new THREE.MeshBasicMaterial({
        color: color, transparent: true, opacity: opacity,
        blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false
      });
      const mesh = new THREE.Mesh(new THREE.TorusGeometry(120, 0.5, 16, 128), mat);
      return mesh;
    };

    const s1 = createGlow(0xffff00, metricsData.blocked_429 > 0 ? 1.0 : 0.1); s1.name = 'glow-429'; s1.rotation.x = Math.PI / 2; s1.rotation.y = -Math.PI / 3; group.add(s1);
    const s2 = createGlow(0x00ff00, metricsData.worker_errors_24h > 0 ? 1.0 : 0.1); s2.name = 'glow-errors'; s2.rotation.x = Math.PI / 2; s2.rotation.y = Math.PI / 3; group.add(s2);
    const s3 = createGlow(0xff0000, metricsData.blocked_403 > 0 ? 1.0 : 0.1); s3.name = 'glow-403'; s3.rotation.x = Math.PI / 2; group.add(s3);
    return group;
  };

  // --- ТАЙМЛАЙН ---
  const drawTimelineBars = (canvas, data) => {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const arr = Array.isArray(data) ? data : [];
    const max = Math.max(1, ...arr.map(b => (b && typeof b.count === 'number') ? b.count : 0));
    const slots = 24;
    const w = canvas.width / slots;
    for (let i = 0; i < slots; i++) {
      const bucket = arr[i] || { count: 0 };
      const ratio = (bucket.count || 0) / max;
      const h = Math.max(0.05, ratio) * canvas.height * 0.9 + canvas.height * 0.05;
      const grad = ctx.createLinearGradient(0, canvas.height, 0, canvas.height - h);
      grad.addColorStop(0, 'rgba(255, 0, 60, 1)'); grad.addColorStop(1, 'rgba(255, 0, 60, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(i * w + 2, canvas.height - h, w - 4, h);
    }
  };

  const createTimeline = (timelineData) => {
    const outer = new THREE.Group();
    const spinner = new THREE.Group();
    outer.add(spinner);
    const canvas = document.createElement('canvas');
    canvas.width = 2048; canvas.height = 256;
    drawTimelineBars(canvas, timelineData);
    const texture = new THREE.CanvasTexture(canvas);
    texture.wrapS = THREE.RepeatWrapping;
    
    const mat = new THREE.MeshBasicMaterial({ map: texture, transparent: true, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false, opacity: 0.9 });
    const mesh = new THREE.Mesh(new THREE.CylinderGeometry(106, 106, 15, 64, 1, true), mat);
    mesh.position.y = 9.5;
    spinner.add(mesh);

    const meshMirror = new THREE.Mesh(new THREE.CylinderGeometry(106, 106, 15, 64, 1, true), mat);
    meshMirror.position.y = -9.5;
    meshMirror.scale.y = -1;
    spinner.add(meshMirror);

    outer.userData.canvas = canvas;
    outer.userData.texture = texture;
    outer.userData.spinner = spinner;
    timelineObjRef.current = outer;
    return outer;
  };

  const customLayerData = useMemo(() => {
    const data = [];
    if (layers.shield) data.push({ type: 'shield', metrics });
    if (layers.timeline) data.push({ type: 'timeline', timeline });
    return data;
  }, [metrics, layers.shield, layers.timeline, timeline]);

  const createObject = (d) => {
    if (d.type === 'shield') return createShield(d.metrics);
    if (d.type === 'timeline') return createTimeline(d.timeline);
    return new THREE.Group();
  };

  const updateObject = (obj, d) => {
    // Мигание вынесено в отдельный цикл requestAnimationFrame для плавности
  };

  useEffect(() => {
    let animId;
    const animate = () => {
      if (timelineObjRef.current && timelineObjRef.current.userData.spinner) {
        const spinner = timelineObjRef.current.userData.spinner;
        const time = performance.now() * 0.001;
        const opacity = 0.6 + Math.sin(time * 4) * 0.3;
        if (spinner.children[0]) spinner.children[0].material.opacity = opacity;
      }
      animId = requestAnimationFrame(animate);
    };
    animate();
    return () => cancelAnimationFrame(animId);
  }, []);

  const handleGlobeReady = () => {
    if (!globeEl.current) return;
    const scene = globeEl.current.scene();
    if (!scene) return;
    globeEl.current.controls().autoRotate = true;
    globeEl.current.controls().autoRotateSpeed = 1.5;
    globeEl.current.pointOfView({ lat: 20, lng: 0, altitude: 4.5 });
  };

  useEffect(() => {
    if (timelineObjRef.current && timelineObjRef.current.userData.canvas) {
      drawTimelineBars(timelineObjRef.current.userData.canvas, timeline);
      timelineObjRef.current.userData.texture.needsUpdate = true;
    }
  }, [timeline]);

  useEffect(() => {
    if (globeEl.current && focusCoords) {
      globeEl.current.controls().autoRotate = false;
      const getAltitude = (code) => {
        const map = { 'AZ': 0.25, 'HK': 0.15, 'NL': 0.35, 'US': 1.3, 'RU': 1.8 };
        return map[code] || 0.6;
      };
      globeEl.current.pointOfView({ lat: focusCoords.lat, lng: focusCoords.lng, altitude: getAltitude(focusCountry) }, 1000);
    } else if (globeEl.current && !focusCoords) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.pointOfView({ lat: 20, lng: 0, altitude: 4.5 }, 1000);
    }
  }, [focusCoords, focusCountry]);

  const ringsBaseData = useMemo(() => (geoData || []).filter(item => countryCoords[item.country] && item.country !== 'XX').map(item => {
    const isFocused = focusCountry === item.country;
    const isDimmed = focusCountry && !isFocused;
    return {
      lat: countryCoords[item.country][0],
      lng: countryCoords[item.country][1],
      name: item.country,
      maxR: 2.5, propSpeed: 2.0, period: 200,
      ringColor: isDimmed ? 'rgba(255, 140, 0, 0.4)' : '#ff8c00'
    };
  }), [geoData, focusCountry]);

  const pointsData = useMemo(() => (geoData || []).filter(item => countryCoords[item.country] && item.country !== 'XX').map(item => {
    const isFocused = focusCountry === item.country;
    const isDimmed = focusCountry && !isFocused;
    return {
      lat: countryCoords[item.country][0],
      lng: countryCoords[item.country][1],
      size: 1.0,
      color: isDimmed ? 'rgba(255, 140, 0, 0.4)' : '#ff8c00',
      name: item.country,
      count: item.count
    };
  }), [geoData, focusCountry, altitude]);

  const scannerRing = {
    lat: 90, lng: 0, maxR: 180, propSpeed: 45, period: 9999999, ringColor: 'rgba(0, 255, 204, 0.8)'
  };

  const [scannerRings, setScannerRings] = useState([]);

  useEffect(() => {
    if (!layers.shield) {
      setScannerRings([]);
      return;
    }
    const spawnWave = () => {
      // Заменяем массив целиком, чтобы старые волны не наслаивались
      setScannerRings([{ ...scannerRing, id: Date.now() }]);
    };
    spawnWave();
    const interval = setInterval(spawnWave, 5000);
    return () => {
      clearInterval(interval);
      setScannerRings([]); // Гарантированно чистим при выключении
    };
  }, [layers.shield]);

  const [pointsRings, setPointsRings] = useState([]);

  useEffect(() => {
    if (!layers.threats) { setPointsRings([]); return; }

    let activeTimeouts = [];

    const spawnBurst = () => {
      const baseId = Date.now();
      // Очищаем старые таймеры перед новым залпом (фикс утечки)
      activeTimeouts.forEach(clearTimeout);
      activeTimeouts = [];

      for (let i = 0; i < 5; i++) {
        activeTimeouts.push(setTimeout(() => {
          setPointsRings(prev => {
            const now = Date.now();
            // Очищаем старые кольца прямо в момент обновления (фикс утечки)
            const recent = prev.filter(r => {
              const ts = parseInt(r.id.split('-')[0]);
              return now - ts < 2500;
            });
            const newRings = ringsBaseData.map(p => ({
              ...p,
              id: baseId + '-' + i + '-' + p.name,
              maxR: p.maxR * (1 + (i * 0.15)),
              period: 9999999
            }));
            return [...recent, ...newRings];
          });
        }, i * 150));
      }
    };

    spawnBurst();
    const interval = setInterval(spawnBurst, 2000);

    return () => {
      clearInterval(interval);
      activeTimeouts.forEach(clearTimeout);
      setPointsRings([]);
    };
  }, [ringsBaseData, layers.threats]);

  const allRings = useMemo(() => {
    let rings = [];
    if (layers.threats) rings.push(...pointsRings);
    if (layers.shield) rings.push(...scannerRings);
    return rings;
  }, [pointsRings, layers.threats, layers.shield, scannerRings]);

  useEffect(() => {
    if (!containerRef.current) return;
    const resizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) setDimensions({ width: entry.contentRect.width, height: entry.contentRect.height });
    });
    resizeObserver.observe(containerRef.current);
    return () => resizeObserver.disconnect();
  }, []);

  return (
    <div ref={containerRef} style={{ cursor: 'grab', height: '100%', width: '100%', position: 'absolute', inset: 0 }}>
      {dimensions.width > 0 && globeMaterial && (
        <Globe
          ref={globeEl}
          width={dimensions.width}
          height={dimensions.height}
          globeMaterial={globeMaterial}
          backgroundColor="rgba(0,0,0,0)"

          atmosphereColor={layers.atmosphere ? "#a855f7" : "rgba(0,0,0,0)"}
          atmosphereAltitude={0.15}

          customLayerData={customLayerData}
          customThreeObject={createObject}
          customThreeObjectUpdate={updateObject}

          pointsData={layers.threats ? pointsData : []}
        onPointClick={(point) => onCountryClick(point.name)}
          pointsMerge={false}
          pointAltitude={(d) => { const MIN_HEIGHT = 0.01; const MAX_HEIGHT = 0.1; const MIN_ALT = 0.1; const MAX_ALT = 4.5; const t = Math.max(0, Math.min(1, (altitude - MIN_ALT) / (MAX_ALT - MIN_ALT))); return MIN_HEIGHT + t * (MAX_HEIGHT - MIN_HEIGHT); }}
        pointsTransitionDuration={0}
          pointRadius={(d) => { const MIN_SIZE = 0.01; const MAX_SIZE = 0.7; const MIN_ALT = 0.1; const MAX_ALT = 4.5; const t = Math.max(0, Math.min(1, (altitude - MIN_ALT) / (MAX_ALT - MIN_ALT))); return d.size * (MIN_SIZE + t * (MAX_SIZE - MIN_SIZE)); }}
          pointColor="color"
          pointLabel={({ name, count }) => `<b>${name}</b>: ${count} requests`}

          ringsData={allRings}
          ringColor={(d) => d.ringColor}
          ringMaxRadius={(d) => d.maxR}
          ringPropagationSpeed={(d) => d.propSpeed}
          ringRepeatPeriod={(d) => d.period}

          onZoom={({ altitude }) => setAltitude(altitude)}
          onGlobeReady={handleGlobeReady}
        />
      )}
    </div>
  );
}
