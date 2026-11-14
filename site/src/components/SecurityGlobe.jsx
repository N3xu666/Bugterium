import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import Globe from 'react-globe.gl';
import * as THREE from 'three';
import { countryCoords } from './countryCoords';

// Degrees-to-world-units factor for ThreeGlobe sphere (R=100)
const GLOBE_PX_PER_DEG = (2 * Math.PI * 100) / 360; // ~1.7453

const getIsLightTheme = () =>
  typeof document !== 'undefined' && document.documentElement?.dataset?.theme === 'light';

// Module-level earth texture material cache to avoid reprocessing 4096x2048 pixels on every lens switch
let cachedDarkGlobeMat = null;
let cachedLightGlobeMat = null;
let globeLoadPromise = null;

const loadGlobeMaterials = () => {
  if (cachedDarkGlobeMat && cachedLightGlobeMat) {
    return Promise.resolve({ dark: cachedDarkGlobeMat, light: cachedLightGlobeMat });
  }
  if (globeLoadPromise) return globeLoadPromise;
  globeLoadPromise = new Promise((resolve) => {
    const img = new Image();
    img.src = '/earth_4k.jpg';
    img.onerror = () => {
      globeLoadPromise = null;
      resolve(null);
    };
    img.onload = () => {
      const w = img.width;
      const h = img.height;

      const darkCanvas = document.createElement('canvas');
      darkCanvas.width = w;
      darkCanvas.height = h;
      const darkCtx = darkCanvas.getContext('2d');
      darkCtx.drawImage(img, 0, 0);

      const srcData = darkCtx.getImageData(0, 0, w, h);
      const lightImgData = darkCtx.createImageData(w, h);
      const dSrc = srcData.data;
      const dLight = lightImgData.data;

      for (let i = 0; i < dSrc.length; i += 4) {
        const r = dSrc[i], g = dSrc[i + 1], b = dSrc[i + 2], a = dSrc[i + 3];
        if (b > r * 1.1) {
          dSrc[i] = 0; dSrc[i + 1] = 0; dSrc[i + 2] = 0;
          dLight[i] = 224; dLight[i + 1] = 224; dLight[i + 2] = 224; dLight[i + 3] = a;
        } else {
          const brightness = (r + g + b) / (255 * 3);
          dSrc[i] = Math.min(255, Math.floor(192 * brightness));
          dSrc[i + 1] = 0;
          dSrc[i + 2] = Math.min(255, Math.floor(48 * brightness));
          const lScale = 0.35 + 0.65 * brightness;
          dLight[i] = Math.min(255, Math.floor(192 * lScale));
          dLight[i + 1] = 0;
          dLight[i + 2] = Math.min(255, Math.floor(48 * lScale));
          dLight[i + 3] = a;
        }
      }

      darkCtx.putImageData(srcData, 0, 0);
      const lightCanvas = document.createElement('canvas');
      lightCanvas.width = w;
      lightCanvas.height = h;
      lightCanvas.getContext('2d').putImageData(lightImgData, 0, 0);

      const darkTex = new THREE.CanvasTexture(darkCanvas);
      darkTex.colorSpace = THREE.SRGBColorSpace;
      darkTex.anisotropy = 16;
      darkTex.minFilter = THREE.LinearFilter;
      darkTex.magFilter = THREE.LinearFilter;

      const lightTex = new THREE.CanvasTexture(lightCanvas);
      lightTex.colorSpace = THREE.SRGBColorSpace;
      lightTex.anisotropy = 16;
      lightTex.minFilter = THREE.LinearFilter;
      lightTex.magFilter = THREE.LinearFilter;

      cachedDarkGlobeMat = new THREE.MeshBasicMaterial({ map: darkTex });
      cachedLightGlobeMat = new THREE.MeshBasicMaterial({ map: lightTex });
      resolve({ dark: cachedDarkGlobeMat, light: cachedLightGlobeMat });
    };
  });
  return globeLoadPromise;
};

// Static accessors prevent unnecessary arc/ring geometry rebuilds in react-kapsule
const getArcStartLat = (d) => d.startLat;
const getArcStartLng = (d) => d.startLng;
const getArcEndLat = (d) => d.endLat;
const getArcEndLng = (d) => d.endLng;
const getArcColor = (d) => d.color;
const getArcAltitude = (d) => d.altitude;
const getArcDashLength = (d) => d.dashLength;
const getArcDashGap = (d) => d.dashGap;
const getArcDashAnimateTime = (d) => d.animateTime;
const getArcLabel = (d) => d.name;
const getRingColor = (d) => d.ringColor;
const getRingMaxRadius = (d) => d.maxR;
const getRingPropagationSpeed = (d) => d.propSpeed;
const getRingRepeatPeriod = (d) => d.period;
const getPointLabel = ({ name, count }) => `<b>${name}</b>: ${count} requests`;

function SecurityGlobe({ geoData, attacksData, focusCoords, focusCountry, metrics, layers, timeline, onCountryClick, focusPath, viewMode }) {
  const globeEl = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [materials, setMaterials] = useState(() => (
    cachedDarkGlobeMat && cachedLightGlobeMat
      ? { dark: cachedDarkGlobeMat, light: cachedLightGlobeMat }
      : null
  ));
  const [isLight, setIsLight] = useState(getIsLightTheme);
  const [altitude, setAltitude] = useState(2.5);
  const lastAltRef = useRef(2.5);

  useEffect(() => {
    const syncTheme = () => setIsLight(getIsLightTheme());
    syncTheme();
    const observer = new MutationObserver(syncTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);

  const handleZoom = useCallback(({ altitude: newAlt }) => {
    // Only update altitude past 0.08 threshold to avoid excessive re-renders while orbiting
    if (Math.abs(newAlt - lastAltRef.current) > 0.08) {
      lastAltRef.current = newAlt;
      setAltitude(Math.round(newAlt * 10) / 10);
    }
  }, []);

  const timelineObjRef = useRef(null);
  const shieldObjRef = useRef(null);

  useEffect(() => {
    let active = true;
    loadGlobeMaterials().then((mats) => {
      if (active && mats) setMaterials(mats);
    });
    return () => { active = false; };
  }, []);

  const globeMaterial = materials ? (isLight ? materials.light : materials.dark) : null;

  // --- SHIELD ---
  const createShield = useCallback((metricsData, lightTheme) => {
    const group = new THREE.Group();
    if (!metricsData) return group;
    const blending = lightTheme ? THREE.NormalBlending : THREE.AdditiveBlending;
    const createGlow = (color, opacity) => {
      const mat = new THREE.MeshBasicMaterial({
        color, transparent: true, opacity,
        blending, side: THREE.DoubleSide, depthWrite: false
      });
      return new THREE.Mesh(new THREE.TorusGeometry(120, 0.5, 16, 128), mat);
    };

    const s1 = createGlow(0xffff00, metricsData.blocked_429 > 0 ? 1.0 : (lightTheme ? 0.25 : 0.1));
    s1.name = 'glow-429'; s1.rotation.x = Math.PI / 2; s1.rotation.y = -Math.PI / 3; group.add(s1);
    const s2 = createGlow(lightTheme ? 0x007700 : 0x00ff00, metricsData.worker_errors_24h > 0 ? 1.0 : (lightTheme ? 0.25 : 0.1));
    s2.name = 'glow-errors'; s2.rotation.x = Math.PI / 2; s2.rotation.y = Math.PI / 3; group.add(s2);
    const s3 = createGlow(lightTheme ? 0xcc0000 : 0xff0000, metricsData.blocked_403 > 0 ? 1.0 : (lightTheme ? 0.25 : 0.1));
    s3.name = 'glow-403'; s3.rotation.x = Math.PI / 2; group.add(s3);
    shieldObjRef.current = group;
    return group;
  }, []);

  // --- TIMELINE ---
  const drawTimelineBars = useCallback((canvas, data) => {
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
      grad.addColorStop(0, 'rgba(168, 85, 247, 1)'); grad.addColorStop(1, 'rgba(168, 85, 247, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(i * w + 2, canvas.height - h, w - 4, h);
    }
  }, []);

  const createTimeline = useCallback((timelineData, lightTheme) => {
    const outer = new THREE.Group();
    const spinner = new THREE.Group();
    outer.add(spinner);
    const canvas = document.createElement('canvas');
    canvas.width = 2048; canvas.height = 256;
    drawTimelineBars(canvas, timelineData);
    const texture = new THREE.CanvasTexture(canvas);
    texture.wrapS = THREE.RepeatWrapping;

    const mat = new THREE.MeshBasicMaterial({
      map: texture,
      transparent: true,
      blending: lightTheme ? THREE.NormalBlending : THREE.AdditiveBlending,
      side: THREE.DoubleSide,
      depthWrite: false,
      opacity: 0.9
    });
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
  }, [drawTimelineBars]);

  const customLayerData = useMemo(() => {
    const data = [];
    if (layers.shield) data.push({ type: 'shield', metrics, isLight });
    if (layers.timeline) data.push({ type: 'timeline', timeline, isLight });
    return data;
  }, [metrics, layers.shield, layers.timeline, timeline, isLight]);

  const createObject = useCallback((d) => {
    if (d.type === 'shield') return createShield(d.metrics, d.isLight);
    if (d.type === 'timeline') return createTimeline(d.timeline, d.isLight);
    return new THREE.Group();
  }, [createShield, createTimeline]);

  const updateObject = useCallback((obj, d) => {
    if (!obj || !d) return;
    const lightTheme = Boolean(d.isLight);
    const blending = lightTheme ? THREE.NormalBlending : THREE.AdditiveBlending;
    if (d.type === 'shield') {
      obj.children.forEach((mesh) => {
        if (!mesh.material) return;
        mesh.material.blending = blending;
        if (mesh.name === 'glow-errors') mesh.material.color.setHex(lightTheme ? 0x007700 : 0x00ff00);
        if (mesh.name === 'glow-403') mesh.material.color.setHex(lightTheme ? 0xcc0000 : 0xff0000);
        mesh.material.needsUpdate = true;
      });
    } else if (d.type === 'timeline' && obj.userData?.spinner) {
      obj.userData.spinner.children.forEach((mesh) => {
        if (mesh.material) {
          mesh.material.blending = blending;
          mesh.material.needsUpdate = true;
        }
      });
    }
  }, []);

  useEffect(() => {
    if (!layers.timeline) return undefined;
    let animId = 0;
    const animate = () => {
      if (typeof document === 'undefined' || !document.hidden) {
        if (timelineObjRef.current && timelineObjRef.current.userData.spinner) {
          const spinner = timelineObjRef.current.userData.spinner;
          const time = performance.now() * 0.001;
          const opacity = 0.6 + Math.sin(time * 4) * 0.3;
          if (spinner.children[0]) spinner.children[0].material.opacity = opacity;
        }
      }
      animId = requestAnimationFrame(animate);
    };
    animate();
    return () => cancelAnimationFrame(animId);
  }, [layers.timeline]);

  const handleGlobeReady = useCallback(() => {
    if (!globeEl.current) return;
    const scene = globeEl.current.scene();
    if (!scene) return;
    globeEl.current.controls().autoRotate = true;
    globeEl.current.controls().autoRotateSpeed = 1.5;
    globeEl.current.pointOfView({ lat: 20, lng: 0, altitude: 4.5 });
  }, []);

  useEffect(() => {
    if (timelineObjRef.current && timelineObjRef.current.userData.canvas) {
      drawTimelineBars(timelineObjRef.current.userData.canvas, timeline);
      timelineObjRef.current.userData.texture.needsUpdate = true;
    }
  }, [timeline, drawTimelineBars]);

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
      maxR: 2.0,
      propSpeed: 1.5,
      period: 200,
      ringColor: isDimmed ? 'rgba(255, 140, 0, 0.25)' : 'rgba(255, 140, 0, 0.8)'
    };
  }), [geoData, focusCountry]);

  // Dynamic node radius in angular degrees
  const getDynamicNodeRadius = useCallback((sizeMultiplier = 1) => {
    const MIN_SIZE = 0.01;
    const MAX_SIZE = 0.7;
    const MIN_ALT = 0.1;
    const MAX_ALT = 4.5;
    const t = Math.max(0, Math.min(1, (altitude - MIN_ALT) / (MAX_ALT - MIN_ALT)));
    return sizeMultiplier * (MIN_SIZE + t * (MAX_SIZE - MIN_SIZE));
  }, [altitude]);

  // Dynamic node cylinder altitude
  const getDynamicNodeHeight = useCallback(() => {
    const MIN_HEIGHT = 0.01;
    const MAX_HEIGHT = 0.1;
    const MIN_ALT = 0.1;
    const MAX_ALT = 4.5;
    const t = Math.max(0, Math.min(1, (altitude - MIN_ALT) / (MAX_ALT - MIN_ALT)));
    return MIN_HEIGHT + t * (MAX_HEIGHT - MIN_HEIGHT);
  }, [altitude]);

  const getPointRadius = useCallback((d) => {
    return getDynamicNodeRadius(d.size);
  }, [getDynamicNodeRadius]);

  // Dynamic arc thickness quantized to 0.02 steps to prevent TubeGeometry churn
  const getDynamicArcStroke = useCallback((sizeMultiplier = 1) => {
    const MIN_SIZE = 0.01;
    const MAX_SIZE = 0.48;
    const MIN_ALT = 0.1;
    const MAX_ALT = 4.5;
    const t = Math.max(0, Math.min(1, (altitude - MIN_ALT) / (MAX_ALT - MIN_ALT)));
    const dynamicRadius = sizeMultiplier * (MIN_SIZE + t * (MAX_SIZE - MIN_SIZE));
    const arcRadiusInScene = dynamicRadius * GLOBE_PX_PER_DEG;
    const rawStroke = 2 * arcRadiusInScene * 0.9;
    return Math.round(rawStroke * 50) / 50;
  }, [altitude]);

  const getArcStroke = useCallback((d) => {
    return getDynamicArcStroke(d.stroke || 0.9);
  }, [getDynamicArcStroke]);

  const pointsData = useMemo(() => (geoData || []).filter(item => countryCoords[item.country] && item.country !== 'XX').map(item => {
    const isFocused = focusCountry === item.country;
    const isDimmed = focusCountry && !isFocused;
    return {
      lat: countryCoords[item.country][0],
      lng: countryCoords[item.country][1],
      size: isFocused ? 1.4 : 0.9,
      color: isDimmed ? 'rgba(255, 140, 0, 0.35)' : '#ff8c00',
      name: item.country,
      count: item.count
    };
  }), [geoData, focusCountry]);

  // Arcs: crimson/red in Suspicious Activity view, monochrome ingress streams otherwise
  const arcsData = useMemo(() => {
    if (!geoData || geoData.length === 0) return [];
    const dest = countryCoords['AZ'] || [40.14, 47.57];
    const isAttackView = viewMode === 'attacks';

    return (geoData || [])
      .filter(item => countryCoords[item.country] && item.country !== 'XX' && item.country !== 'AZ')
      .map(item => {
        const coords = countryCoords[item.country];
        const isFocused = focusCountry === item.country;
        const count = item.count || 1;

        let arcColors;
        let arcLabel;
        if (isAttackView) {
          arcColors = isFocused
            ? ['rgba(255, 0, 0, 0.75)', 'rgba(192, 0, 48, 0.75)']
            : ['rgba(255, 0, 0, 0.22)', 'rgba(192, 0, 48, 0.22)'];
          arcLabel = `⚠️ ${item.country} → ATTACK VECTOR [${count} threat probes]`;
        } else if (isLight) {
          arcColors = isFocused
            ? ['rgba(26, 26, 26, 0.75)', 'rgba(26, 26, 26, 0.65)']
            : ['rgba(26, 26, 26, 0.22)', 'rgba(26, 26, 26, 0.22)'];
          arcLabel = `🌐 ${item.country} → INGRESS STREAM [${count} requests]`;
        } else {
          arcColors = isFocused
            ? ['rgba(255, 255, 255, 0.8)', 'rgba(215, 215, 215, 0.75)']
            : ['rgba(255, 255, 255, 0.22)', 'rgba(215, 215, 215, 0.22)'];
          arcLabel = `🌐 ${item.country} → INGRESS STREAM [${count} requests]`;
        }

        return {
          startLat: coords[0],
          startLng: coords[1],
          endLat: dest[0],
          endLng: dest[1],
          name: arcLabel,
          color: arcColors,
          stroke: isFocused ? 1.4 : 0.9,
          altitude: Math.min(0.45, 0.16 + Math.log10(Math.max(1, count)) * 0.08),
          dashLength: isAttackView ? 0.4 : 0.5,
          dashGap: isAttackView ? 0.15 : 0.2,
          animateTime: isAttackView
            ? Math.max(1000, 2200 - Math.min(count, 500) * 2)
            : 2400
        };
      });
  }, [geoData, focusCountry, viewMode, isLight]);

  const scannerRing = useMemo(() => ({
    lat: 90,
    lng: 0,
    maxR: 180,
    propSpeed: 45,
    period: 9999999,
    ringColor: isLight ? 'rgba(0, 119, 0, 0.8)' : 'rgba(0, 255, 102, 0.8)'
  }), [isLight]);

  const [scannerRings, setScannerRings] = useState([]);

  useEffect(() => {
    if (!layers.shield) {
      setScannerRings([]);
      return;
    }
    const spawnWave = () => {
      setScannerRings([{ ...scannerRing, id: Date.now() }]);
    };
    spawnWave();
    const interval = setInterval(spawnWave, 5000);
    return () => {
      clearInterval(interval);
      setScannerRings([]);
    };
  }, [layers.shield, scannerRing]);

  const [pointsRings, setPointsRings] = useState([]);

  useEffect(() => {
    if (!layers.threats) { setPointsRings([]); return; }

    let activeTimeouts = [];

    const spawnBurst = () => {
      const baseId = Date.now();
      activeTimeouts.forEach(clearTimeout);
      activeTimeouts = [];

      for (let i = 0; i < 5; i++) {
        activeTimeouts.push(setTimeout(() => {
          setPointsRings(prev => {
            const now = Date.now();
            const recent = prev.filter(r => {
              const ts = parseInt(r.id.split('-')[0], 10);
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
      for (const entry of entries) setDimensions({ width: entry.contentRect.width, height: entry.contentRect.height });
    });
    resizeObserver.observe(containerRef.current);
    return () => resizeObserver.disconnect();
  }, []);

  const handlePointClick = useCallback((point) => {
    if (onCountryClick && point?.name) onCountryClick(point.name);
  }, [onCountryClick]);

  return (
    <div ref={containerRef} style={{ cursor: 'grab', height: '100%', width: '100%', position: 'absolute', inset: 0 }}>
      {dimensions.width > 0 && globeMaterial && (
        <Globe
          ref={globeEl}
          width={dimensions.width}
          height={dimensions.height}
          globeMaterial={globeMaterial}
          backgroundColor="rgba(0,0,0,0)"

          atmosphereColor={layers.atmosphere ? '#c00030' : 'rgba(0,0,0,0)'}
          atmosphereAltitude={0.15}

          customLayerData={customLayerData}
          customThreeObject={createObject}
          customThreeObjectUpdate={updateObject}

          pointsData={layers.threats ? pointsData : []}
          onPointClick={handlePointClick}
          pointsMerge={false}
          pointAltitude={getDynamicNodeHeight}
          pointsTransitionDuration={0}
          pointRadius={getPointRadius}
          pointColor="color"
          pointLabel={getPointLabel}

          ringsData={allRings}
          ringColor={getRingColor}
          ringMaxRadius={getRingMaxRadius}
          ringPropagationSpeed={getRingPropagationSpeed}
          ringRepeatPeriod={getRingRepeatPeriod}

          arcsData={layers.threats ? arcsData : []}
          arcsTransitionDuration={0}
          arcCurveResolution={36}
          arcCircularResolution={4}
          arcStartLat={getArcStartLat}
          arcStartLng={getArcStartLng}
          arcEndLat={getArcEndLat}
          arcEndLng={getArcEndLng}
          arcColor={getArcColor}
          arcAltitude={getArcAltitude}
          arcStroke={getArcStroke}
          arcDashLength={getArcDashLength}
          arcDashGap={getArcDashGap}
          arcDashAnimateTime={getArcDashAnimateTime}
          arcLabel={getArcLabel}

          onZoom={handleZoom}
          onGlobeReady={handleGlobeReady}
        />
      )}
    </div>
  );
}

export default React.memo(SecurityGlobe);