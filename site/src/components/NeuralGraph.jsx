import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import '../css/neural-graph.css';

const HOME = '_home';
const RENDERER_CONFIG = { antialias: true, alpha: true };

const getIsLightTheme = () =>
  typeof document !== 'undefined' && document.documentElement?.dataset?.theme === 'light';

const GEO = new THREE.SphereGeometry(1, 16, 16);
const MAT = {
  home: new THREE.MeshBasicMaterial({ color: 0xffffff }),
  index: new THREE.MeshBasicMaterial({ color: 0xffffff }),
  file: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xa855f7).multiplyScalar(2.5) }),
  tool: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xff0000).multiplyScalar(2.5) }),
  cve: new THREE.MeshBasicMaterial({ color: 0xff8c00 }),
  mitre: new THREE.MeshBasicMaterial({ color: new THREE.Color(0x00ff66).multiplyScalar(2.2) }),
};

const _dir = new THREE.Vector3();
const _up = new THREE.Vector3(0, 1, 0);

const linkPoints = [];
for (let i = 0; i <= 12; i++) {
  const t = i / 12;
  // Taper thickness: 0.3 at base endpoints, 0.05 at midpoint
  const radius = 0.3 - Math.sin(t * Math.PI) * 0.25;
  linkPoints.push(new THREE.Vector2(radius, t - 0.5));
}
const LINK_GEO = new THREE.LatheGeometry(linkPoints, 8);
const LINK_SHADER_VERT = `
  uniform float uThicknessZoneA;
  uniform float uThicknessZoneB;
  uniform float uSphereRadiusA;
  uniform float uSphereRadiusB;
  uniform float uThicknessBoostA;
  uniform float uThicknessBoostB;
  varying float vT;
  varying float vDistFromA;
  varying float vDistFromB;
  void main() {
    vT = position.y + 0.5;
    float linkLength = length(modelMatrix[1].xyz);
    vDistFromA = vT * linkLength;
    vDistFromB = (1.0 - vT) * linkLength;
    float dEffA = max(0.0, vDistFromA - uSphereRadiusA);
    float dEffB = max(0.0, vDistFromB - uSphereRadiusB);
    float normA = clamp(dEffA / uThicknessZoneA, 0.0, 1.0);
    float normB = clamp(dEffB / uThicknessZoneB, 0.0, 1.0);
    float thickA = 1.0 + (uThicknessBoostA - 1.0) * pow(1.0 - normA, 2.0);
    float thickB = 1.0 + (uThicknessBoostB - 1.0) * pow(1.0 - normB, 2.0);
    float thick = max(thickA, thickB);
    vec3 pos = vec3(position.x * thick, position.y, position.z * thick);
    gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
  }
`;
const LINK_SHADER_FRAG = `
  uniform vec3 uColorA;
  uniform vec3 uColorB;
  uniform vec3 uMidColor;
  uniform float uOpacity;
  uniform float uColorZoneA;
  uniform float uColorZoneB;
  uniform float uTransitionZone;
  varying float vT;
  varying float vDistFromA;
  varying float vDistFromB;
  void main() {
    vec3 base = mix(uColorA, uColorB, vT);
    float tA = smoothstep(uColorZoneA, uColorZoneA + uTransitionZone, vDistFromA);
    float tB = smoothstep(uColorZoneB, uColorZoneB + uTransitionZone, vDistFromB);
    float peak = min(tA, tB);
    vec3 col = mix(base, uMidColor, peak);
    gl_FragColor = vec4(col, uOpacity);
  }
`;
const getNodeRole = (node) => {
  if (!node) return 'file';
  if (node.id === HOME || node.is_index) return 'home';
  if (node.group === 'tool' || node.group === 'cve' || node.group === 'mitre') return node.group;
  return 'file';
};
const roleToHex = (role, isLight = false) => {
  if (role === 'home') return isLight ? 0x1a1a1a : 0xffffff;
  if (role === 'tool') return isLight ? 0xc00030 : 0xff0000;
  if (role === 'cve') return isLight ? 0xff8800 : 0xff8c00;
  if (role === 'mitre') return isLight ? 0x007700 : 0x00ff66;
  return 0xa855f7;
};
const hexToRole = (hex) => {
  if (hex === 0xffffff || hex === 0x1a1a1a) return 'home';
  if (hex === 0xff0000 || hex === 0xc00030) return 'tool';
  if (hex === 0xff8c00 || hex === 0xff8800) return 'cve';
  if (hex === 0x00ff66 || hex === 0x007700) return 'mitre';
  return 'file';
};
const getNodeColorHex = (node, isLight = false) => roleToHex(getNodeRole(node), isLight);

const sphereRadiusFor = (hex) => {
  if (hex === 0xff0000 || hex === 0xc00030) return 2.5;
  if (hex === 0xff8c00 || hex === 0xff8800) return 2.0;
  if (hex === 0x00ff66 || hex === 0x007700) return 2.2;
  if (hex === 0xa855f7) return 1.4;
  if (hex === 0xffffff || hex === 0x1a1a1a) return 2.2;
  return 1.4;
};
const thicknessBoostFor = (hex) => {
  if (hex === 0xff0000 || hex === 0xc00030) return 3.0;
  if (hex === 0xff8c00 || hex === 0xff8800) return 5.7;
  if (hex === 0x00ff66 || hex === 0x007700) return 4.5;
  if (hex === 0xa855f7) return 2.5;
  if (hex === 0xffffff || hex === 0x1a1a1a) return 2.0;
  return 4.0;
};
const thicknessZoneFor = (hex) => {
  return 1.5 + (thicknessBoostFor(hex) - 4.0) * 0.3;
};
const LINK_MAT_CACHE = new Map();
const applyLinkMatTheme = (mat, isLight) => {
  const { srcRole, tgtRole } = mat.userData;
  const bright = (srcRole === 'tool' || tgtRole === 'tool' || srcRole === 'cve' || tgtRole === 'cve');
  const isFullOpacity = (srcRole === 'file' && tgtRole === 'tool') || (srcRole === 'tool' && tgtRole === 'file') || srcRole === 'cve' || tgtRole === 'cve';
  mat.uniforms.uColorA.value.setHex(roleToHex(srcRole, isLight));
  mat.uniforms.uColorB.value.setHex(roleToHex(tgtRole, isLight));
  mat.uniforms.uMidColor.value.setHex(isLight ? 0x1a1a1a : 0xffffff);
  mat.uniforms.uOpacity.value = isFullOpacity ? 1.0 : (bright ? 0.85 : (isLight ? 0.45 : 0.35));
};
const applyThemeToMaterials = (isLight) => {
  if (isLight) {
    MAT.home.color.setHex(0x1a1a1a);
    MAT.index.color.setHex(0x1a1a1a);
    MAT.file.color.setHex(0xa855f7);
    MAT.tool.color.setHex(0xc00030);
    MAT.cve.color.setHex(0xff8800);
    MAT.mitre.color.setHex(0x007700);
  } else {
    MAT.home.color.setHex(0xffffff);
    MAT.index.color.setHex(0xffffff);
    MAT.file.color.setHex(0xa855f7).multiplyScalar(2.5);
    MAT.tool.color.setHex(0xff0000).multiplyScalar(2.5);
    MAT.cve.color.setHex(0xff8c00);
    MAT.mitre.color.setHex(0x00ff66).multiplyScalar(2.2);
  }
  for (const mat of LINK_MAT_CACHE.values()) {
    applyLinkMatTheme(mat, isLight);
  }
};
const getLinkMaterial = (srcHex, tgtHex, isLight = false) => {
  const key = srcHex * 0x1000000 + tgtHex;
  let mat = LINK_MAT_CACHE.get(key);
  if (mat) return mat;
  const srcRole = hexToRole(srcHex);
  const tgtRole = hexToRole(tgtHex);
  const bright = (srcRole === 'tool' || tgtRole === 'tool' || srcRole === 'cve' || tgtRole === 'cve');
  const isFullOpacity = (srcRole === 'file' && tgtRole === 'tool') || (srcRole === 'tool' && tgtRole === 'file') || srcRole === 'cve' || tgtRole === 'cve';
  mat = new THREE.ShaderMaterial({
    uniforms: {
      uColorA: { value: new THREE.Color(srcHex) },
      uColorB: { value: new THREE.Color(tgtHex) },
      uMidColor: { value: new THREE.Color(isLight ? 0x1a1a1a : 0xffffff) },
      uOpacity: { value: isFullOpacity ? 1.0 : (bright ? 0.85 : (isLight ? 0.45 : 0.35)) },
      uColorZoneA: { value: sphereRadiusFor(srcHex) + 3.0 },
      uColorZoneB: { value: sphereRadiusFor(tgtHex) + 3.0 },
      uTransitionZone: { value: 8.0 },
      uThicknessZoneA: { value: thicknessZoneFor(srcHex) },
      uThicknessZoneB: { value: thicknessZoneFor(tgtHex) },
      uSphereRadiusA: { value: sphereRadiusFor(srcHex) },
      uSphereRadiusB: { value: sphereRadiusFor(tgtHex) },
      uThicknessBoostA: { value: thicknessBoostFor(srcHex) },
      uThicknessBoostB: { value: thicknessBoostFor(tgtHex) },
    },
    vertexShader: LINK_SHADER_VERT,
    fragmentShader: LINK_SHADER_FRAG,
    transparent: true,
    side: THREE.DoubleSide,
  });
  mat.userData.srcRole = srcRole;
  mat.userData.tgtRole = tgtRole;
  LINK_MAT_CACHE.set(key, mat);
  return mat;
};

const PLACEHOLDER_MAT = new THREE.MeshBasicMaterial({ color: 0x888888, opacity: 0.3, transparent: true, side: THREE.DoubleSide });
const getLinkObject = () => {
  const mesh = new THREE.Mesh(LINK_GEO, PLACEHOLDER_MAT);
  mesh.frustumCulled = false;
  mesh.userData.matKey = null;
  return mesh;
};

const updateLinkPosition = (obj, { start, end }, link, nodeMap, isLight = false) => {
  if (!obj) return false;
  const srcNode = typeof link.source === 'object' ? link.source : (nodeMap ? nodeMap.get(link.source) : null);
  const tgtNode = typeof link.target === 'object' ? link.target : (nodeMap ? nodeMap.get(link.target) : null);
  const curSrcHex = getNodeColorHex(srcNode, isLight);
  const curTgtHex = getNodeColorHex(tgtNode, isLight);
  const curKey = curSrcHex * 0x1000000 + curTgtHex;
  if (obj.userData.matKey !== curKey) {
    obj.material = getLinkMaterial(curSrcHex, curTgtHex, isLight);
    obj.userData.matKey = curKey;
  }

  let s = start;
  let e = end;
  if (!s || typeof s.x !== 'number') s = link.source;
  if (!e || typeof e.x !== 'number') e = link.target;
  if (!s || !e || typeof s.x !== 'number' || typeof e.x !== 'number') return false;

  const dx = e.x - s.x;
  const dy = e.y - s.y;
  const dz = e.z - s.z;
  const length = Math.sqrt(dx * dx + dy * dy + dz * dz);

  if (length === 0) return false;

  obj.position.set(s.x + dx / 2, s.y + dy / 2, s.z + dz / 2);
  obj.scale.set(1, length, 1);

  _dir.set(dx, dy, dz).normalize();
  obj.quaternion.setFromUnitVectors(_up, _dir);

  return true; // Tell library position/transform was handled manually
};

const getNodeObject = (node) => {
  let mat = MAT.file;
  let scale = 1.4;
  if (node.id === HOME) { mat = MAT.home; scale = 3.5; }
  else if (node.group === 'tool') { mat = MAT.tool; scale = 2.5; }
  else if (node.group === 'cve') { mat = MAT.cve; scale = 2.0; }
  else if (node.group === 'mitre') { mat = MAT.mitre; scale = 2.2; }
  else if (node.is_index) { mat = MAT.index; scale = 2.2; }

  const mesh = new THREE.Mesh(GEO, mat);
  mesh.scale.set(scale, scale, scale);
  return mesh;
};

const getNodeLabel = (node) => {
  if (node.id === HOME) return 'Bugterium';
  return node.label || node.id;
};

const readFocusFromUrl = () => {
  if (typeof window === 'undefined') return null;
  const q = new URLSearchParams(window.location.search);
  return q.get('focus') || null;
};

const buildVisible = (graph, focus, activeFilter) => {
  if (!graph || !graph.hierarchy || !graph.brain) return { nodes: [], links: [] };
  const tree = graph.hierarchy.tree;
  const allBrainNodes = graph.brain.nodes;
  const nodeMap = new Map(allBrainNodes.map(n => [n.id, n]));

  let baseData = graph.brain;

  if (focus) {
    if (focus.startsWith('tool:') || focus.startsWith('cve:') || focus.startsWith('mitre:')) {
      const connectedIds = new Set([focus]);
      const visibleLinks = [];
      for (const l of graph.brain.links) {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        if (s === focus || t === focus) {
          connectedIds.add(s);
          connectedIds.add(t);
          visibleLinks.push(l);
        }
      }
      const nodes = Array.from(connectedIds).map(id => nodeMap.get(id)).filter(Boolean);
      baseData = { nodes, links: visibleLinks };
    } else {
      // 1. Gather all descendants of focus
      const baseIds = new Set();
      const addDescendants = (id) => {
        baseIds.add(id);
        const n = tree[id];
        if (n && n.children) n.children.forEach(addDescendants);
      };
      addDescendants(focus);

      // 2. Gather neural links where source is in baseIds (captures tools/CVEs/mitre)
      const visibleIds = new Set([...baseIds]);
      const visibleLinks = [];
      const seenLinks = new Set();

      for (const l of graph.brain.links) {
        const s = l.source.id || l.source;
        const t = l.target.id || l.target;
        if (baseIds.has(s)) {
          visibleIds.add(s);
          visibleIds.add(t);
          const key = s + '->' + t;
          if (!seenLinks.has(key)) {
            seenLinks.add(key);
            visibleLinks.push(l);
          }
        }
      }

      // 3. Add hierarchy links for structure (parent-child)
      for (const l of graph.hierarchy.links) {
        const s = l.source.id || l.source;
        const t = l.target.id || l.target;
        if (baseIds.has(s) && baseIds.has(t)) {
          const key = s + '->' + t;
          if (!seenLinks.has(key)) {
            seenLinks.add(key);
            visibleLinks.push(l);
          }
        }
      }

      const nodes = Array.from(visibleIds).map(id => nodeMap.get(id)).filter(Boolean);
      baseData = { nodes, links: visibleLinks };
    }
  }

  if (activeFilter) {
    const matchingIds = new Set();
    baseData.nodes.forEach(n => {
      if (activeFilter === 'cve' && n.group === 'cve') matchingIds.add(n.id);
      else if (activeFilter === 'mitre' && n.group === 'mitre') matchingIds.add(n.id);
      else if (activeFilter === 'tool' && n.group === 'tool') matchingIds.add(n.id);
      else if (activeFilter === 'file' && !n.group && !n.is_index && n.id !== HOME) matchingIds.add(n.id);
      else if (activeFilter === 'index' && (n.is_index || n.id === HOME)) matchingIds.add(n.id);
    });

    const activeNodeIds = new Set(matchingIds);
    const activeLinks = [];
    baseData.links.forEach(l => {
      const s = typeof l.source === 'object' ? l.source.id : l.source;
      const t = typeof l.target === 'object' ? l.target.id : l.target;
      if (matchingIds.has(s) || matchingIds.has(t)) {
        activeNodeIds.add(s);
        activeNodeIds.add(t);
        activeLinks.push(l);
      }
    });

    const filteredNodes = baseData.nodes.filter(n => activeNodeIds.has(n.id));
    return { nodes: filteredNodes, links: activeLinks };
  }

  return baseData;
};

const getNodeCountForFocus = (targetFocus, g, activeFilter) => {
  if (!targetFocus || !g || !g.brain) return g?.brain?.nodes?.length || 944;
  const vis = buildVisible(g, targetFocus, activeFilter);
  return (vis && vis.nodes) ? vis.nodes.length : 944;
};

const getCameraDistance = (nodeCount, embedded = false) => {
  const mult = embedded ? 41 : 33;
  const offset = embedded ? 20 : 15;
  const minD = embedded ? 140 : 110;
  const maxD = embedded ? 1300 : 1050;
  return Math.min(maxD, Math.max(minD, Math.round(mult * Math.sqrt(nodeCount) + offset)));
};

function NeuralGraph({ onReady, embedded = false, onBackToLenses }) {
  const [graph, setGraph] = useState(null);
  const [focus, setFocus] = useState(null);
  const [activeFilter, setActiveFilter] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const searchInputRef = useRef(null);

  const [size, setSize] = useState({ width: 0, height: 0 });
  const [error, setError] = useState(null);
  const [isReady, setIsReady] = useState(false);
  const [fading, setFading] = useState(false);
  const fadeTimerRef = useRef(null);
  const searchTimerRef = useRef(null);
  const isLightRef = useRef(getIsLightTheme());

  useEffect(() => {
    return () => {
      if (fadeTimerRef.current) clearTimeout(fadeTimerRef.current);
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (isReady && onReady) onReady();
  }, [isReady, onReady]);
  const [alphaDecay, setAlphaDecay] = useState(0.003);
  const [velocityDecay, setVelocityDecay] = useState(0.1);
  const containerRef = useRef(null);
  const graphRef = useRef(null);
  const bloomAddedRef = useRef(false);
  const bloomPassRef = useRef(null);
  const nodeMapRef = useRef(new Map());
  const graphDataRef = useRef(graph);
  const tickCount = useRef(0);

  useEffect(() => {
    const syncTheme = () => {
      const light = getIsLightTheme();
      isLightRef.current = light;
      applyThemeToMaterials(light);
      if (bloomPassRef.current) {
        bloomPassRef.current.enabled = !light;
        if (!light) bloomPassRef.current.strength = 0.35;
      }
    };
    syncTheme();
    const observer = new MutationObserver(syncTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    graphDataRef.current = graph;
    if (graph && graph.brain) {
      const m = new Map();
      graph.brain.nodes.forEach((n) => m.set(n.id, n));
      nodeMapRef.current = m;
    }
  }, [graph]);

  const updateLinkPositionCb = useCallback((obj, params, link) => {
    return updateLinkPosition(obj, params, link, nodeMapRef.current, isLightRef.current);
  }, []);

  useEffect(() => {
    setFocus(readFocusFromUrl());
    const onPop = () => setFocus(readFocusFromUrl());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  useEffect(() => {
    fetch('/graph.json')
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(setGraph)
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setSize({ width: el.clientWidth, height: el.clientHeight });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const visible = useMemo(() => buildVisible(graph, focus, activeFilter), [graph, focus, activeFilter]);

  const selectedConnections = useMemo(() => {
    if (!selectedNode || !graph || !graph.brain) return [];
    const id = selectedNode.id;
    const connected = [];
    const allNodes = nodeMapRef.current;
    for (const l of graph.brain.links) {
      const s = typeof l.source === 'object' ? l.source.id : l.source;
      const t = typeof l.target === 'object' ? l.target.id : l.target;
      if (s === id && allNodes.has(t)) connected.push(allNodes.get(t));
      else if (t === id && allNodes.has(s)) connected.push(allNodes.get(s));
    }
    return connected.slice(0, 16);
  }, [selectedNode, graph]);

  const searchResults = useMemo(() => {
    if (!searchQuery.trim() || !graph || !graph.brain) return [];
    const q = searchQuery.toLowerCase().trim();
    const results = [];
    for (const n of graph.brain.nodes) {
      const label = (n.label || '').toLowerCase();
      const id = (n.id || '').toLowerCase();
      if (label.includes(q) || id.includes(q)) {
        results.push(n);
        if (results.length >= 8) break;
      }
    }
    return results;
  }, [searchQuery, graph]);

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg || visible.nodes.length === 0) return;
    if (fg.controls()) fg.controls().zoomSpeed = 2.5;
    
    // Physics: spread nodes apart
    if (fg.d3Force('charge')) fg.d3Force('charge').strength(-30);
    if (fg.d3Force('link')) fg.d3Force('link').distance(10);
    tickCount.current = 0;
    setAlphaDecay(0.003);
    fg.d3ReheatSimulation();
    if (!bloomAddedRef.current) {
      const el = containerRef.current;
      const w = el ? el.clientWidth : 800;
      const h = el ? el.clientHeight : 600;
      const bloomPass = new UnrealBloomPass(new THREE.Vector2(w, h), 0.35, 0.5, 0.3);
      bloomPass.enabled = !isLightRef.current;
      bloomPassRef.current = bloomPass;
      fg.postProcessingComposer().addPass(bloomPass);
      bloomAddedRef.current = true;
    }
  }, [visible]);

  useEffect(() => {
    if (bloomPassRef.current && graphRef.current && size.width > 0 && size.height > 0) {
      const pr = graphRef.current.renderer()?.getPixelRatio?.() || 1;
      bloomPassRef.current.setSize(size.width * pr, size.height * pr);
    }
  }, [size]);

  const focusOnNode = useCallback((node) => {
    if (!node) return;
    setSelectedNode(node);
    if (graphRef.current && typeof node.x === 'number') {
      const dist = 70;
      graphRef.current.cameraPosition(
        { x: node.x + dist, y: node.y + dist * 0.4, z: node.z + dist },
        { x: node.x, y: node.y, z: node.z },
        1000
      );
    }
  }, []);

  const resetCameraToFocus = useCallback((targetFocus) => {
    const g = graphRef.current;
    if (!g) return;
    if (g.controls()) {
      g.controls().target.set(0, 0, 0);
    }
    const count = getNodeCountForFocus(targetFocus, graphDataRef.current, activeFilter);
    const targetDist = getCameraDistance(count, embedded);
    const cam = g.camera();
    const curX = cam ? cam.position.x : 0;
    const curY = cam ? cam.position.y : 0;
    const curZ = cam ? cam.position.z : targetDist;
    const curLen = Math.sqrt(curX * curX + curY * curY + curZ * curZ);

    let nextX = 0, nextY = 0, nextZ = targetDist;
    if (curLen > 10) {
      nextX = (curX / curLen) * targetDist;
      nextY = (curY / curLen) * targetDist;
      nextZ = (curZ / curLen) * targetDist;
    }

    g.cameraPosition(
      { x: nextX, y: nextY, z: nextZ },
      { x: 0, y: 0, z: 0 },
      700
    );
  }, [embedded, activeFilter]);

  const goTo = useCallback((nextFocus) => {
    const url = new URL(window.location.href);
    if (nextFocus) url.searchParams.set('focus', nextFocus);
    else url.searchParams.delete('focus');
    window.history.pushState({}, '', url.toString());
    setFocus(nextFocus);
    setSelectedNode(null);

    resetCameraToFocus(nextFocus);
  }, [resetCameraToFocus]);

  useEffect(() => {
    const onFocusNodeEvent = (e) => {
      if (!e.detail) return;
      const targetId = e.detail.id;
      const node = (nodeMapRef.current && nodeMapRef.current.get(targetId)) || 
                   (graph && graph.brain && graph.brain.nodes.find(n => n.id === targetId || n.label === e.detail.label));
      if (node) {
        focusOnNode(node);
      } else {
        // Live CISA KEV vulnerability not yet documented in local repository
        setSelectedNode({
          id: e.detail.id,
          label: e.detail.label,
          group: 'cve',
          unmapped: true,
          cvss: e.detail.cvss,
          epss: e.detail.epss,
          description: e.detail.description,
          url: e.detail.url || `https://nvd.nist.gov/vuln/detail/${e.detail.label}`
        });
      }
    };
    window.addEventListener('bugterium-focus-node', onFocusNodeEvent);
    return () => window.removeEventListener('bugterium-focus-node', onFocusNodeEvent);
  }, [graph, focusOnNode]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === '/' && document.activeElement !== searchInputRef.current) {
        e.preventDefault();
        setIsSearchOpen(true);
        if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
        searchTimerRef.current = setTimeout(() => searchInputRef.current?.focus(), 50);
        return;
      }
      if (e.key === 'Escape') {
        if (isSearchOpen || searchQuery) {
          setIsSearchOpen(false);
          setSearchQuery('');
          return;
        }
        if (selectedNode) {
          setSelectedNode(null);
          resetCameraToFocus(focus);
          return;
        }
        if (!focus) return;
        if (focus.startsWith('tool:') || focus.startsWith('cve:') || focus.startsWith('mitre:')) { goTo(null); return; }
        const node = graph && graph.hierarchy ? graph.hierarchy.tree[focus] : null;
        goTo(node && node.parent ? node.parent : null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [focus, graph, goTo, isSearchOpen, searchQuery, selectedNode, resetCameraToFocus]);

  const handleNodeClick = useCallback((node) => {
    if (!node) return;
    if (node.id === HOME) { goTo(null); setSelectedNode(null); return; }
    focusOnNode(node);
  }, [goTo, focusOnNode]);

  const crumbs = useMemo(() => {
    if (!graph || !graph.hierarchy) return [];
    const list = [{ id: HOME, label: 'Bugterium' }];
    if (!focus) return list;
    if (focus.startsWith('tool:') || focus.startsWith('cve:') || focus.startsWith('mitre:')) {
      const n = graph.brain.nodes.find((x) => x.id === focus);
      list.push({ id: focus, label: n ? n.label : focus });
      return list;
    }
    const ids = [];
    let cur = focus;
    while (cur && graph.hierarchy.tree[cur]) {
      ids.unshift(cur);
      cur = graph.hierarchy.tree[cur].parent;
    }
    for (const id of ids) {
      const n = graph.hierarchy.tree[id];
      list.push({ id, label: (n && n.label) || id });
    }
    return list;
  }, [graph, focus]);

  const status = error
    ? 'LOAD ERROR: ' + error
    : visible.nodes.length + ' nodes / ' + visible.links.length + ' links' ;

  const cameraPos = useMemo(() => ({ x: 0, y: 0, z: embedded ? 1280 : 1000 }), [embedded]);

  const toggleFilter = useCallback((type) => {
    setActiveFilter(prev => prev === type ? null : type);
  }, []);

  const handleNodeHover = useCallback((node) => {
    document.body.style.cursor = node ? 'pointer' : 'default';
  }, []);

  const handleEngineTick = useCallback(() => {
    tickCount.current++;
    if (tickCount.current === 40) setAlphaDecay(0.015);
    else if (tickCount.current === 80) setAlphaDecay(0.06);
    else if (tickCount.current === 120) setAlphaDecay(0.15);
  }, []);

  const handleEngineStop = useCallback(() => {
    setIsReady(true);
    setFading(true);
    if (fadeTimerRef.current) clearTimeout(fadeTimerRef.current);
    fadeTimerRef.current = setTimeout(() => setFading(false), 500);
  }, []);

  return (
    <div 
      className="app"
      style={embedded ? {
        position: 'relative',
        inset: 'auto',
        width: '100%',
        height: '100%',
        zIndex: 1,
        display: 'grid',
        gridTemplateRows: '40px 1fr 40px'
      } : undefined}
    >
      <header className="hud">
        <span className="brand">
          <span 
            className="brand-prefix"
            onClick={onBackToLenses}
            style={{ cursor: onBackToLenses ? 'pointer' : 'default' }}
            title="Return to Lenses Hub"
          >
            BUGTERIUM
          </span>
          <span className="sep">/</span> 
          {onBackToLenses ? (
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
              onClick={onBackToLenses}
              title="Return to Lenses Hub"
            >
              LENSES
            </button>
          ) : 'NEURAL PORT'}
        </span>
        <nav className="crumbs">
          <span className="crumb-item">
            <span className="crumb" style={{ cursor: 'default', pointerEvents: 'none' }}>
              NEURAL PORT
            </span>
          </span>
          <span className="sep">/</span>
          {crumbs.map((c, i) => {
            const isRoot = c.id === HOME;
            const label = isRoot ? 'ROOT' : c.label;
            return (
              <span key={c.id} className="crumb-item">
                {i > 0 && <span className="sep">/</span>}
                <button
                  type="button"
                  className={'crumb' + (i === crumbs.length - 1 ? ' active' : '')}
                  onClick={() => goTo(isRoot ? null : c.id)}
                >
                  {label}
                </button>
              </span>
            );
          })}
        </nav>
        <span className="status">{status}</span>
      </header>

      <main className="stage" ref={containerRef}>
        <div className="port-search-wrap" style={{ position: 'absolute', top: '14px', right: '16px', zIndex: 60 }}>
          <div className="hud-search-wrap">
            <input
              ref={searchInputRef}
              type="text"
              className="hud-search-input"
              placeholder="SEARCH NODES [/]..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setIsSearchOpen(true);
              }}
              onFocus={() => setIsSearchOpen(true)}
              onBlur={() => setTimeout(() => setIsSearchOpen(false), 200)}
            />
            {isSearchOpen && searchResults.length > 0 && (
              <div className="hud-search-dropdown" style={{ right: 0, left: 'auto' }}>
                {searchResults.map((res) => {
                  const grp = res.group || (res.is_index ? 'index' : 'file');
                  return (
                    <button
                      key={res.id}
                      type="button"
                      className="hud-search-item"
                      onMouseDown={(e) => {
                        e.preventDefault();
                        focusOnNode(res);
                        setIsSearchOpen(false);
                        setSearchQuery('');
                      }}
                    >
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                        {res.label || res.id}
                      </span>
                      <span className={`hud-search-badge badge-${grp}`}>
                        {grp.toUpperCase()}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {(!isReady || fading) && (
          <div className={"loading-overlay" + (fading ? " fading" : "")}>
            <div className="loading-text">INITIALIZING NEURAL PORT...</div>
            <div className="loading-bar"><div className="loading-bar-fill"></div></div>
          </div>
        )}

        <div className="legend-box">
          <div className="legend-items">
            <div className={`legend-item ${activeFilter === 'cve' ? 'active' : ''}`} onClick={() => toggleFilter('cve')}>
              <span className="legend-dot dot-cve"></span>
              <span className="legend-text">CVE</span>
            </div>
            <div className={`legend-item ${activeFilter === 'mitre' ? 'active' : ''}`} onClick={() => toggleFilter('mitre')}>
              <span className="legend-dot dot-mitre"></span>
              <span className="legend-text">MITRE</span>
            </div>
            <div className={`legend-item ${activeFilter === 'tool' ? 'active' : ''}`} onClick={() => toggleFilter('tool')}>
              <span className="legend-dot dot-tool"></span>
              <span className="legend-text">Tool</span>
            </div>
            <div className={`legend-item ${activeFilter === 'file' ? 'active' : ''}`} onClick={() => toggleFilter('file')}>
              <span className="legend-dot dot-file"></span>
              <span className="legend-text">File</span>
            </div>
            <div className={`legend-item ${activeFilter === 'index' ? 'active' : ''}`} onClick={() => toggleFilter('index')}>
              <span className="legend-dot dot-home"></span>
              <span className="legend-text">Folder</span>
            </div>
            {activeFilter && (
              <button type="button" className="legend-reset" onClick={() => setActiveFilter(null)}>
                RESET FILTER
              </button>
            )}
          </div>
        </div>

        {selectedNode && (
          <div className="entity-card">
            <div className="entity-card-header">
              <div className="entity-badge" data-group={selectedNode.group || (selectedNode.is_index ? 'index' : 'file')}>
                {selectedNode.unmapped ? 'LIVE THREAT' : (selectedNode.group ? selectedNode.group.toUpperCase() : (selectedNode.is_index ? 'CATEGORY' : 'FILE'))}
              </div>
              <button type="button" className="entity-close-btn" onClick={() => { setSelectedNode(null); resetCameraToFocus(focus); }} title="Close inspector">✕</button>
            </div>
            <div className="entity-title">{selectedNode.label || selectedNode.id}</div>
            
            {selectedNode.unmapped && (
              <div style={{ background: 'rgba(255, 140, 0, 0.12)', border: '1px solid var(--warn)', padding: '8px 10px', fontSize: '10px', color: 'var(--warn)', lineHeight: '1.4' }}>
                <div style={{ fontWeight: '600', marginBottom: '4px' }}>⚡ CISA KEV ACTIVE ZERO-DAY</div>
                <div>{selectedNode.description || 'Active exploited in the wild.'}</div>
                <div style={{ marginTop: '4px', color: 'var(--dim)', fontStyle: 'italic' }}>
                  Not yet in local repository writeups.
                </div>
              </div>
            )}

            {!selectedNode.unmapped && selectedNode.group === 'cve' && (
              <div className="entity-meta">Known Vulnerability Identifier · NVD NIST Reference Available</div>
            )}
            {selectedNode.group === 'mitre' && (
              <div className="entity-meta">MITRE ATT&CK Adversary Technique · Enterprise Matrix</div>
            )}
            {selectedNode.group === 'tool' && (
              <div className="entity-meta">Offensive / Defensive Tooling Reference</div>
            )}
            {!selectedNode.group && !selectedNode.is_index && (
              <div className="entity-meta">Knowledge Base / HTB Walkthrough Reference</div>
            )}

            {selectedNode.url && (
              <a 
                href={selectedNode.url} 
                target={selectedNode.url.startsWith('http') ? '_blank' : '_self'}
                rel="noopener noreferrer"
                className="entity-action-btn"
              >
                {selectedNode.url.startsWith('http') ? 'OPEN EXTERNAL REF ↗' : 'OPEN WRITEUP / DOC ↗'}
              </a>
            )}

            {selectedNode.is_index && selectedNode.id !== HOME && (
              <button 
                type="button" 
                className="entity-action-btn"
                onClick={() => goTo(selectedNode.id)}
              >
                DRILL INTO SECTION ↓
              </button>
            )}

            {selectedConnections.length > 0 && (
              <div className="entity-connections">
                <div className="entity-connections-title">CONNECTED NODES ({selectedConnections.length}):</div>
                <div className="entity-tags">
                  {selectedConnections.map(cn => (
                    <button 
                      key={cn.id} 
                      type="button"
                      className="entity-tag" 
                      data-group={cn.group || 'file'}
                      onClick={() => focusOnNode(cn)}
                    >
                      {cn.label || cn.id}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {size.width > 0 && visible.nodes.length > 0 && (
          <ForceGraph3D
            ref={graphRef}
            graphData={visible}
            width={size.width}
            height={size.height}
            backgroundColor="rgba(0,0,0,0)"
            cameraPosition={cameraPos}
            nodeThreeObject={getNodeObject}
            nodeLabel={getNodeLabel}
            onNodeClick={handleNodeClick}
            onNodeHover={handleNodeHover}
            linkThreeObject={getLinkObject}
            linkPositionUpdate={updateLinkPositionCb}
            rendererConfig={RENDERER_CONFIG}
            showNavInfo={false}
            warmupTicks={0}
            cooldownTicks={200}
            cooldownTime={4000}
            d3AlphaDecay={alphaDecay}
            d3VelocityDecay={velocityDecay}
            onEngineTick={handleEngineTick}
            onEngineStop={handleEngineStop}
          />
        )}
        
        <div className='custom-nav-info'>
          <div>Left-click: inspect node / rotate</div>
          <div>Mouse-wheel: zoom</div>
          <div>Right-click: pan</div>
          <div>Key [/]: quick search · [Esc]: close/up</div>
        </div>
        {!error && (!graph || visible.nodes.length === 0) && (
          <p className="hint">{graph ? 'empty focus' : ''}</p>
        )}
      </main>
      <footer className="hud foot">
        <span>SYSTEM READY</span>
        <span>Press Esc to go up · click node to inspect · [/] to search</span>
      </footer>
    </div>
  );
}

export default React.memo(NeuralGraph);
