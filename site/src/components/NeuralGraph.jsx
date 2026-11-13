import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import '../css/neural-graph.css';

const HOME = '_home';

const GEO = new THREE.SphereGeometry(1, 16, 16);
const MAT = {
  home: new THREE.MeshBasicMaterial({ color: 0xffffff }),
  index: new THREE.MeshBasicMaterial({ color: 0xffffff }),
  file: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xa855f7).multiplyScalar(2.5) }),
  tool: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xff0000).multiplyScalar(2.5) }),
  cve: new THREE.MeshBasicMaterial({ color: 0xff8c00 }),
  mitre: new THREE.MeshBasicMaterial({ color: new THREE.Color(0x00ff66).multiplyScalar(2.2) }),
};

const linkPoints = [];
for (let i = 0; i <= 30; i++) {
  const t = i / 30;
  // Толщина: 0.3 у основания, 0.05 в середине
  const radius = 0.3 - Math.sin(t * Math.PI) * 0.25;
  linkPoints.push(new THREE.Vector2(radius, t - 0.5));
}
const LINK_GEO = new THREE.LatheGeometry(linkPoints, 32);
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
    vec3 col = mix(base, vec3(1.0), peak);
    gl_FragColor = vec4(col, uOpacity);
  }
`;
const getNodeColorHex = (node) => {
  if (!node) return 0xa855f7;
  if (node.id === HOME) return 0xffffff;
  if (node.group === 'tool') return 0xff0000;
  if (node.group === 'cve') return 0xff8c00;
  if (node.group === 'mitre') return 0x00ff66;
  if (node.is_index) return 0xffffff;
  return 0xa855f7;
};
const sphereRadiusFor = (hex) => {
  if (hex === 0xff0000) return 2.5;
  if (hex === 0xff8c00) return 2.0;
  if (hex === 0x00ff66) return 2.2;
  if (hex === 0xa855f7) return 1.4;
  if (hex === 0xffffff) return 2.2;
  return 1.4;
};
const thicknessBoostFor = (hex) => {
  if (hex === 0xff0000) return 3.0;
  if (hex === 0xff8c00) return 5.7;
  if (hex === 0x00ff66) return 4.5;
  if (hex === 0xa855f7) return 2.5;
  if (hex === 0xffffff) return 2.0;
  return 4.0;
};
const thicknessZoneFor = (hex) => {
  return 1.5 + (thicknessBoostFor(hex) - 4.0) * 0.3;
};
const LINK_MAT_CACHE = new Map();
const getLinkMaterial = (srcHex, tgtHex) => {
  const key = srcHex.toString(16).padStart(6, '0') + '_' + tgtHex.toString(16).padStart(6, '0');
  let mat = LINK_MAT_CACHE.get(key);
  if (mat) return mat;
  const bright = (srcHex === 0xff0000 || tgtHex === 0xff0000 || srcHex === 0xff8c00 || tgtHex === 0xff8c00);
  const isFullOpacity = (srcHex === 0xa855f7 && tgtHex === 0xff0000) || (srcHex === 0xff0000 && tgtHex === 0xa855f7) || srcHex === 0xff8c00 || tgtHex === 0xff8c00;
  mat = new THREE.ShaderMaterial({
    uniforms: {
      uColorA: { value: new THREE.Color(srcHex) },
      uColorB: { value: new THREE.Color(tgtHex) },
      uOpacity: { value: isFullOpacity ? 1.0 : (bright ? 0.85 : 0.35) },
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

const updateLinkPosition = (obj, { start, end }, link, nodeMap) => {
  if (!obj) return false;
  const srcNode = typeof link.source === 'object' ? link.source : (nodeMap ? nodeMap.get(link.source) : null);
  const tgtNode = typeof link.target === 'object' ? link.target : (nodeMap ? nodeMap.get(link.target) : null);
  const curSrcHex = getNodeColorHex(srcNode);
  const curTgtHex = getNodeColorHex(tgtNode);
  const curKey = curSrcHex.toString(16).padStart(6, '0') + '_' + curTgtHex.toString(16).padStart(6, '0');
  if (obj.userData.matKey !== curKey) {
    obj.material = getLinkMaterial(curSrcHex, curTgtHex);
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
  const length = Math.sqrt(dx*dx + dy*dy + dz*dz);
  
  if (length === 0) return false;

  obj.position.set(s.x + dx/2, s.y + dy/2, s.z + dz/2);
  obj.scale.set(1, length, 1);

  const dir = new THREE.Vector3(dx, dy, dz).normalize();
  const up = new THREE.Vector3(0, 1, 0);
  obj.quaternion.setFromUnitVectors(up, dir);

  return true; // КРИТИЧЕСКИ ВАЖНО: говорим библиотеке, что мы всё обновили
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

export default function NeuralGraph({ onReady, embedded = false, onBackToLenses }) {
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

  useEffect(() => {
    return () => {
      if (fadeTimerRef.current) clearTimeout(fadeTimerRef.current);
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
  const nodeMapRef = useRef(new Map());
  const graphDataRef = useRef(graph);
  const tickCount = useRef(0);

  useEffect(() => {
    graphDataRef.current = graph;
    if (graph && graph.brain) {
      const m = new Map();
      graph.brain.nodes.forEach((n) => m.set(n.id, n));
      nodeMapRef.current = m;
    }
  }, [graph]);

  const updateLinkPositionCb = useCallback((obj, params, link) => {
    return updateLinkPosition(obj, params, link, nodeMapRef.current);
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
    
    // Физика: раздвигаем узлы
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
      fg.postProcessingComposer().addPass(bloomPass);
      bloomAddedRef.current = true;
    }
  }, [visible]);

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
        // Уязвимость из живого фида CISA KEV еще не задокументирована в репозитории
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
        setTimeout(() => searchInputRef.current?.focus(), 50);
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
  }, [focus, graph, goTo, isSearchOpen, searchQuery, selectedNode]);

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

  const toggleFilter = (type) => {
    setActiveFilter(prev => prev === type ? null : type);
  };

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
              <div style={{ background: 'rgba(255, 140, 0, 0.12)', border: '1px solid rgba(255, 140, 0, 0.4)', padding: '8px 10px', fontSize: '10px', color: '#ffb347', lineHeight: '1.4' }}>
                <div style={{ fontWeight: '600', marginBottom: '4px' }}>⚡ CISA KEV ACTIVE ZERO-DAY</div>
                <div>{selectedNode.description || 'Active exploited in the wild.'}</div>
                <div style={{ marginTop: '4px', color: '#aaaaaa', fontStyle: 'italic' }}>
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
            style={{ opacity: 1 }}
            ref={graphRef}
            graphData={visible}
            width={size.width}
            height={size.height}
            backgroundColor="#000000"
            cameraPosition={{ x: 0, y: 0, z: embedded ? 1280 : 1000 }}
            nodeThreeObject={getNodeObject}
            nodeLabel={getNodeLabel}
            onNodeClick={handleNodeClick}
            onNodeHover={(node) => {
              if (!node) { document.body.style.cursor = 'default'; return; }
              document.body.style.cursor = 'pointer';
            }}
            linkColor={(l) => {
              const tgt = typeof l.target === 'object' ? l.target : { id: l.target };
              const src = typeof l.source === 'object' ? l.source : { id: l.source };
              if (tgt.group === 'tool' || src.group === 'tool') return '#c00030';
              if (tgt.group === 'cve' || src.group === 'cve') return '#ff8c00';
              if (tgt.group === 'mitre' || src.group === 'mitre') return '#00ff66';
              return '#aaaaaa';
            }}
            linkThreeObject={getLinkObject}
            linkPositionUpdate={updateLinkPositionCb}
            rendererConfig={{ antialias: true, alpha: false }}
            showNavInfo={false}
            warmupTicks={0}
            cooldownTicks={200}
            d3AlphaDecay={alphaDecay}
            d3VelocityDecay={velocityDecay}
            onEngineTick={() => {
              tickCount.current++;
              if (tickCount.current === 40) setAlphaDecay(0.015);
              else if (tickCount.current === 80) setAlphaDecay(0.06);
              else if (tickCount.current === 120) setAlphaDecay(0.15);
            }}
            onEngineStop={() => {
              setIsReady(true);
              setFading(true);
              if (fadeTimerRef.current) clearTimeout(fadeTimerRef.current);
              fadeTimerRef.current = setTimeout(() => setFading(false), 500);
            }}
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
