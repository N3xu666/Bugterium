import React, { useEffect, useRef, useState, useMemo } from 'react';
import Globe from 'react-globe.gl';
import * as THREE from 'three';
import { countryCoords } from './countryCoords';

export default function SecurityGlobe({ geoData, focusCoords, focusCountry, metrics, layers, timeline }) {
  const globeEl = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [globeMaterial, setGlobeMaterial] = useState(null);
  const [altitude, setAltitude] = useState(2.5);

  const animFrameRef = useRef();
  const orbitObjectsRef = useRef([]);

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
    const m1 = new THREE.MeshBasicMaterial({ color: 0x00ff00, transparent: true, opacity: metricsData.blocked_429 > 0 ? 0.8 : 0.05, blending: THREE.AdditiveBlending, side: THREE.DoubleSide });
    const s1 = new THREE.Mesh(new THREE.TorusGeometry(104, 0.6, 3, 64), m1); s1.rotation.x = Math.PI / 2; group.add(s1);
    const m2 = new THREE.MeshBasicMaterial({ color: 0xff8c00, transparent: true, opacity: metricsData.blocked_403 > 0 ? 0.8 : 0.05, blending: THREE.AdditiveBlending, side: THREE.DoubleSide });
    const s2 = new THREE.Mesh(new THREE.TorusGeometry(110, 0.6, 3, 64), m2); s2.rotation.x = Math.PI / 2; s2.rotation.y = Math.PI / 3; group.add(s2);
    const m3 = new THREE.MeshBasicMaterial({ color: 0xff0000, transparent: true, opacity: metricsData.worker_errors_24h > 0 ? 0.8 : 0.05, blending: THREE.AdditiveBlending, side: THREE.DoubleSide });
    const s3 = new THREE.Mesh(new THREE.TorusGeometry(116, 0.6, 3, 64), m3); s3.rotation.x = Math.PI / 2; s3.rotation.y = -Math.PI / 3; group.add(s3);
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
    const group = new THREE.Group();
    const canvas = document.createElement('canvas');
    canvas.width = 2048; canvas.height = 256;
    drawTimelineBars(canvas, timelineData);
    const texture = new THREE.CanvasTexture(canvas);
    texture.wrapS = THREE.RepeatWrapping;
    const mesh = new THREE.Mesh(
      new THREE.CylinderGeometry(106, 106, 15, 64, 1, true),
      new THREE.MeshBasicMaterial({ map: texture, transparent: true, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, depthWrite: false, opacity: 0.9 })
    );
    group.userData.canvas = canvas;
    group.userData.texture = texture;
    group.add(mesh);
    return group;
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
    if (d.type === 'timeline' && obj.children[0]) {
      const time = Date.now() * 0.001;
      obj.rotation.y = time * 0.1;
      obj.children[0].material.opacity = 0.6 + Math.sin(time * 4) * 0.3;
      if (obj.userData && obj.userData.canvas && obj.userData.texture) {
        drawTimelineBars(obj.userData.canvas, d.timeline);
        obj.userData.texture.needsUpdate = true;
      }
    }
  };

  // --- ОРБИТЫ (3D) ---
  const handleGlobeReady = () => {
    if (!globeEl.current) return;
    const scene = globeEl.current.scene();
    if (!scene) return;
    globeEl.current.controls().autoRotate = true;
    globeEl.current.controls().autoRotateSpeed = 1.5;

    const orbitConfigs = [
      { r: 130, color: 0x00ffff, tiltX: Math.PI / 4, tiltY: 0, speed: 0.8 },
      { r: 145, color: 0xa855f7, tiltX: -Math.PI / 3, tiltY: Math.PI / 4, speed: 1.2 },
      { r: 160, color: 0xff003c, tiltX: Math.PI / 6, tiltY: -Math.PI / 3, speed: 1.5 }
    ];

    orbitObjectsRef.current = [];
    orbitConfigs.forEach((cfg) => {
      const group = new THREE.Group();
      group.add(new THREE.Mesh(new THREE.TorusGeometry(cfg.r, 0.2, 8, 64), new THREE.MeshBasicMaterial({ color: cfg.color, transparent: true, opacity: 0.3, blending: THREE.AdditiveBlending })));
      const pMesh = new THREE.Mesh(new THREE.SphereGeometry(1.5, 8, 8), new THREE.MeshBasicMaterial({ color: '#ffffff' }));
      group.add(pMesh);
      group.rotation.x = cfg.tiltX;
      group.rotation.y = cfg.tiltY;
      
      group.visible = layers.traffic; // Устанавливаем изначальную видимость
      
      scene.add(group);
      orbitObjectsRef.current.push({ group, pMesh, r: cfg.r, speed: cfg.speed });
    });

    const animate = () => {
      const time = Date.now() * 0.001;
      orbitObjectsRef.current.forEach(o => {
        o.pMesh.position.x = Math.cos(time * o.speed) * o.r;
        o.pMesh.position.y = Math.sin(time * o.speed) * o.r;
      });
      animFrameRef.current = requestAnimationFrame(animate);
    };
    cancelAnimationFrame(animFrameRef.current);
    animate();
  };

  // Обновляем видимость орбит при изменении состояния
  useEffect(() => {
    if (orbitObjectsRef.current) {
      orbitObjectsRef.current.forEach(o => {
        o.group.visible = layers.traffic;
      });
    }
  }, [layers.traffic]);

  useEffect(() => () => cancelAnimationFrame(animFrameRef.current), []);

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
      globeEl.current.pointOfView({ altitude: 2.5 }, 1000);
    }
  }, [focusCoords, focusCountry]);

  // --- ТОЧКИ СТРАН И ПУЛЬСИРУЮЩИЕ КОЛЬЦА ---
  const pointsData = (geoData || []).filter(item => countryCoords[item.country] && item.country !== 'XX').map(item => {
    const isFocused = focusCountry === item.country;
    const isDimmed = focusCountry && !isFocused;
    const sizeScale = Math.max(0.01, Math.min(1.5, Math.pow(altitude / 2.5, 3)));
    const baseSize = Math.log(item.count + 1) * (isFocused ? 0.25 : 0.15);
    
    return { 
      lat: countryCoords[item.country][0], 
      lng: countryCoords[item.country][1], 
      size: baseSize * sizeScale, 
      color: isFocused ? '#ffffff' : (isDimmed ? 'rgba(255, 140, 0, 0.15)' : '#ff8c00'), 
      name: item.country, 
      count: item.count,
      maxR: 2.5, propSpeed: 1.5, period: 1500,
      ringColor: isFocused ? '#ffffff' : (isDimmed ? 'rgba(255, 140, 0, 0.1)' : '#ff8c00')
    };
  });

  // --- СКАНЕР (Нативные кольца) ---
  const scannerRing = {
    lat: 90, lng: 0, maxR: 180, propSpeed: 45, period: 4000, ringColor: 'rgba(0, 255, 204, 0.8)' 
  };
  
  // Формируем кольца только если слои включены
  const allRings = useMemo(() => {
    let rings = [];
    if (layers.threats) rings.push(...pointsData);
    if (layers.scanner) rings.push(scannerRing);
    return rings;
  }, [pointsData, layers.threats, layers.scanner]);

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
          
          /* Атмосфера */
          atmosphereColor={layers.atmosphere ? "#a855f7" : "rgba(0,0,0,0)"} 
          atmosphereAltitude={0.15} 
          
          customLayerData={customLayerData}
          customThreeObject={createObject}
          customThreeObjectUpdate={updateObject}

          /* Точки */
          pointsData={layers.threats ? pointsData : []} 
          pointsMerge={true} 
          pointAltitude={0} 
          pointRadius="size" 
          pointColor="color" 
          pointLabel={({ name, count }) => `<b>${name}</b>: ${count} requests`} 
          
          /* Кольца */
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