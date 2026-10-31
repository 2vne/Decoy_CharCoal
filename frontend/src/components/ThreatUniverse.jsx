import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { useSoc } from '../context/SocContext';
import {
  Shield,
  RotateCcw,
  Search,
  Eye,
  EyeOff,
  Radio,
  X,
  Play,
  Pause,
  Maximize2,
  Layers,
  ChevronRight,
  Share2,
} from 'lucide-react';

// Color Palette for Threat Bands
const BAND_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#10b981',
};

// Colors for Relationship Edge Types
const EDGE_COLORS = {
  same_fingerprint: '#00f0ff',
  shared_credentials: '#a855f7',
  shared_malware: '#ef4444',
  same_honeypot_window: '#eab308',
};

// Procedural texture generator for realistic threat planets
function createProceduralPlanetTexture(threatType) {
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 128;
  const ctx = canvas.getContext('2d');
  const type = (threatType || 'recon').toLowerCase();

  let base1 = '#1a0505';
  let base2 = '#5a1010';
  let accent = '#ff3300';

  if (type.includes('ddos') || type.includes('flood')) {
    base1 = '#260404'; base2 = '#801005'; accent = '#ff2a00';
  } else if (type.includes('malware') || type.includes('trojan')) {
    base1 = '#140008'; base2 = '#4a031f'; accent = '#b3003b';
  } else if (type.includes('sql') || type.includes('inject')) {
    base1 = '#1a0c00'; base2 = '#662b00'; accent = '#ff6a00';
  } else if (type.includes('brute') || type.includes('credential')) {
    base1 = '#000f26'; base2 = '#003380'; accent = '#0088ff';
  } else if (type.includes('phish')) {
    base1 = '#001a24'; base2 = '#005973'; accent = '#00c3ff';
  } else if (type.includes('xss') || type.includes('script')) {
    base1 = '#160026'; base2 = '#490080'; accent = '#9d00ff';
  } else if (type.includes('scan') || type.includes('recon')) {
    base1 = '#001a1c'; base2 = '#004a4f'; accent = '#00ffc4';
  } else {
    base1 = '#211700'; base2 = '#5c4300'; accent = '#e6aa00';
  }

  const grad = ctx.createLinearGradient(0, 0, 256, 128);
  grad.addColorStop(0, base1);
  grad.addColorStop(0.5, base2);
  grad.addColorStop(1, base1);
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 256, 128);

  ctx.globalAlpha = 0.35;
  for (let y = 0; y < 128; y += 8) {
    ctx.fillStyle = (y % 16 === 0) ? accent : base2;
    ctx.beginPath();
    ctx.moveTo(0, y);
    for (let x = 0; x <= 256; x += 32) {
      ctx.lineTo(x, y + Math.sin((x / 256) * Math.PI * 4 + y * 0.1) * 4);
    }
    ctx.lineTo(256, y + 8);
    ctx.lineTo(0, y + 8);
    ctx.closePath();
    ctx.fill();
  }

  ctx.globalAlpha = 0.55;
  ctx.strokeStyle = accent;
  ctx.lineWidth = 1;
  for (let i = 0; i < 12; i++) {
    ctx.beginPath();
    let cx = Math.random() * 256;
    let cy = Math.random() * 128;
    ctx.moveTo(cx, cy);
    for (let s = 0; s < 4; s++) {
      cx += (Math.random() - 0.5) * 30;
      cy += (Math.random() - 0.5) * 20;
      ctx.lineTo(cx, cy);
    }
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  const texture = new THREE.CanvasTexture(canvas);
  texture.wrapS = THREE.RepeatWrapping;
  texture.wrapT = THREE.ClampToEdgeWrapping;
  return texture;
}

// Procedural texture for Central Sun
function createSunTexture() {
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 128;
  const ctx = canvas.getContext('2d');
  const g = ctx.createLinearGradient(0, 0, 256, 128);
  g.addColorStop(0, '#ff4500');
  g.addColorStop(0.5, '#ffa500');
  g.addColorStop(1, '#ff3300');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, 256, 128);

  for (let i = 0; i < 80; i++) {
    const x = Math.random() * 256;
    const y = Math.random() * 128;
    const r = 4 + Math.random() * 14;
    const rg = ctx.createRadialGradient(x, y, 0, x, y, r);
    rg.addColorStop(0, 'rgba(255,255,200,0.6)');
    rg.addColorStop(1, 'rgba(255,60,0,0)');
    ctx.fillStyle = rg;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();
  }
  const tex = new THREE.CanvasTexture(canvas);
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.RepeatWrapping;
  return tex;
}

export default function ThreatUniverse({ height = 650, isPreview = false, onExpand }) {
  const mountRef = useRef(null);
  const {
    attackers,
    relationships,
    setSelectedAttackerId,
    selectedAttackerId,
  } = useSoc();

  // UI state
  const [activeBandFilter, setActiveBandFilter] = useState('all');
  const [showRelationships, setShowRelationships] = useState(true);
  const [showOrbits, setShowOrbits] = useState(true);
  const [showLabels, setShowLabels] = useState(true);
  const [showEdges, setShowEdges] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [hoveredPlanetId, setHoveredPlanetId] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [planetScreens, setPlanetScreens] = useState([]);
  const [clockTime, setClockTime] = useState(new Date().toUTCString());

  // Refs for animation loop
  const isPausedRef = useRef(false);
  const showLabelsRef = useRef(true);
  const showEdgesRef = useRef(true);
  const showOrbitsRef = useRef(true);
  const selectedIdRef = useRef(null);
  const hoveredIdRef = useRef(null);
  const sceneRef = useRef(null);
  const cameraRef = useRef(null);
  const rendererRef = useRef(null);
  const controlsRef = useRef(null);
  const rafRef = useRef(null);
  const planetsMapRef = useRef(new Map());
  const sunMeshRef = useRef(null);
  const sunRingsRef = useRef([]);
  const edgeLinesRef = useRef([]);
  const targetCameraPosRef = useRef(null);

  // Keep refs synchronized
  useEffect(() => { isPausedRef.current = isPaused; }, [isPaused]);
  useEffect(() => { showLabelsRef.current = showLabels; }, [showLabels]);
  useEffect(() => { showEdgesRef.current = showEdges; }, [showEdges]);
  useEffect(() => { showOrbitsRef.current = showOrbits; }, [showOrbits]);
  useEffect(() => { selectedIdRef.current = selectedAttackerId; }, [selectedAttackerId]);
  useEffect(() => { hoveredIdRef.current = hoveredPlanetId; }, [hoveredPlanetId]);

  // Filtered & sorted attacker list
  const displayedAttackers = useMemo(() => {
    let list = attackers || [];
    if (activeBandFilter !== 'all') {
      list = list.filter((a) => a.risk_band === activeBandFilter);
    }
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      list = list.filter(
        (a) => a.ip?.toLowerCase().includes(q) || (a.intent && a.intent.toLowerCase().includes(q))
      );
    }
    return [...list].sort((a, b) => (b.total_events || 0) - (a.total_events || 0));
  }, [attackers, activeBandFilter, searchTerm]);

  const threatCounts = useMemo(() => {
    const c = { total: (attackers || []).length, critical: 0, high: 0, medium: 0, low: 0 };
    (attackers || []).forEach((a) => {
      if (c[a.risk_band] !== undefined) c[a.risk_band]++;
    });
    return c;
  }, [attackers]);

  // Live ticking clock
  useEffect(() => {
    const t = setInterval(() => setClockTime(new Date().toUTCString()), 1000);
    return () => clearInterval(t);
  }, []);

  // Initialize Three.js Scene once
  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const W = container.clientWidth || 1200;
    const H = container.clientHeight || height || 650;

    // 1. Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color('#030712');
    scene.fog = new THREE.FogExp2('#030712', 0.007);
    sceneRef.current = scene;

    // 2. Camera
    const camera = new THREE.PerspectiveCamera(45, W / H, 0.3, 1200);
    camera.position.set(0, 24, 46);
    camera.lookAt(0, 0, 0);
    cameraRef.current = camera;

    // 3. Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.2;
    rendererRef.current = renderer;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // 4. Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.06;
    controls.minDistance = 10;
    controls.maxDistance = 100;
    controls.maxPolarAngle = Math.PI / 2 + 0.2;
    controlsRef.current = controls;

    // 5. Lights
    scene.add(new THREE.AmbientLight('#2a3754', 1.2));
    const sunLight = new THREE.PointLight('#ffaa44', 5.0, 140, 1.2);
    sunLight.position.set(0, 0, 0);
    scene.add(sunLight);
    const rimLight = new THREE.DirectionalLight('#00f0ff', 0.7);
    rimLight.position.set(20, 30, 20);
    scene.add(rimLight);

    // 6. Deep Space Stars
    const starCount = 1800;
    const starPos = new Float32Array(starCount * 3);
    const starCol = new Float32Array(starCount * 3);
    for (let i = 0; i < starCount; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(Math.random() * 2 - 1);
      const r = 160 + Math.random() * 100;
      starPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      starPos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      starPos[i * 3 + 2] = r * Math.cos(phi);
      const mix = Math.random();
      if (mix > 0.8) {
        starCol[i * 3] = 0.4; starCol[i * 3 + 1] = 0.9; starCol[i * 3 + 2] = 1.0;
      } else if (mix > 0.6) {
        starCol[i * 3] = 1.0; starCol[i * 3 + 1] = 0.6; starCol[i * 3 + 2] = 0.4;
      } else {
        starCol[i * 3] = 0.9; starCol[i * 3 + 1] = 0.95; starCol[i * 3 + 2] = 1.0;
      }
    }
    const starsGeo = new THREE.BufferGeometry();
    starsGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
    starsGeo.setAttribute('color', new THREE.BufferAttribute(starCol, 3));
    scene.add(new THREE.Points(starsGeo, new THREE.PointsMaterial({
      size: 0.9, vertexColors: true, transparent: true, opacity: 0.85, sizeAttenuation: true,
    })));

    // 7. Nebula Clusters
    const nebCount = 120;
    const nebPos = new Float32Array(nebCount * 3);
    for (let i = 0; i < nebCount; i++) {
      nebPos[i * 3] = (Math.random() - 0.5) * 150;
      nebPos[i * 3 + 1] = (Math.random() - 0.5) * 25 - 4;
      nebPos[i * 3 + 2] = (Math.random() - 0.5) * 150;
    }
    const nebGeo = new THREE.BufferGeometry();
    nebGeo.setAttribute('position', new THREE.BufferAttribute(nebPos, 3));
    scene.add(new THREE.Points(nebGeo, new THREE.PointsMaterial({
      size: 1.8, color: '#00ffff', transparent: true, opacity: 0.10,
      blending: THREE.AdditiveBlending, sizeAttenuation: true,
    })));

    // 8. Central Sun
    const sunTex = createSunTexture();
    const sunMesh = new THREE.Mesh(
      new THREE.SphereGeometry(2.4, 48, 48),
      new THREE.MeshStandardMaterial({ map: sunTex, emissive: '#ff7700', emissiveIntensity: 1.8, roughness: 0.3 })
    );
    scene.add(sunMesh);
    sunMeshRef.current = sunMesh;

    // Sun glowing corona
    sunMesh.add(new THREE.Mesh(
      new THREE.SphereGeometry(2.4 * 1.22, 32, 32),
      new THREE.MeshBasicMaterial({ color: '#ff9900', transparent: true, opacity: 0.22, blending: THREE.AdditiveBlending, side: THREE.BackSide })
    ));
    sunMesh.add(new THREE.Mesh(
      new THREE.SphereGeometry(2.4 * 1.55, 32, 32),
      new THREE.MeshBasicMaterial({ color: '#ff4400', transparent: true, opacity: 0.09, blending: THREE.AdditiveBlending, side: THREE.BackSide })
    ));

    // Sun rings
    const rings = [];
    [2.4 * 1.7, 2.4 * 2.3, 2.4 * 2.9].forEach((r, idx) => {
      const rMesh = new THREE.Mesh(
        new THREE.RingGeometry(r - 0.04, r + 0.04, 64),
        new THREE.MeshBasicMaterial({
          color: idx === 1 ? '#00f0ff' : '#ffaa00',
          transparent: true,
          opacity: 0.4,
          side: THREE.DoubleSide,
          blending: THREE.AdditiveBlending,
        })
      );
      rMesh.rotation.x = Math.PI / 2 + idx * 0.18;
      rMesh.rotation.y = idx * 0.25;
      scene.add(rMesh);
      rings.push({ mesh: rMesh, speed: (idx % 2 === 0 ? 1 : -1) * 0.004 });
    });
    sunRingsRef.current = rings;

    // Resize listener
    const handleResize = () => {
      if (!container || !camera || !renderer) return;
      const nW = container.clientWidth || 1200;
      const nH = container.clientHeight || height || 650;
      camera.aspect = nW / nH;
      camera.updateProjectionMatrix();
      renderer.setSize(nW, nH);
    };
    window.addEventListener('resize', handleResize);

    // Animation Loop
    const loop = () => {
      rafRef.current = requestAnimationFrame(loop);

      if (sunMeshRef.current) sunMeshRef.current.rotation.y += 0.0025;
      sunRingsRef.current.forEach((r) => { r.mesh.rotation.z += r.speed; });

      const screenCoords = [];

      planetsMapRef.current.forEach((obj, id) => {
        if (!isPausedRef.current) {
          obj.angle += obj.speed;
          obj.mesh.rotation.y += obj.rotSpeed;
        }
        const R = obj.orbitRadius;
        obj.mesh.position.x = Math.cos(obj.angle) * R;
        obj.mesh.position.z = Math.sin(obj.angle) * R;
        obj.mesh.position.y = Math.sin(obj.angle * 2.1) * 0.6;

        const isSelected = selectedIdRef.current === id;
        const isHovered = hoveredIdRef.current === id;
        if (obj.atmo) {
          obj.atmo.scale.setScalar(isSelected ? 1.5 : isHovered ? 1.35 : 1.18);
          obj.atmo.material.opacity = isSelected ? 0.65 : isHovered ? 0.45 : 0.22;
        }

        if (obj.orbitLine) {
          obj.orbitLine.visible = showOrbitsRef.current;
        }

        if (showLabelsRef.current && cameraRef.current && mountRef.current) {
          const wp = new THREE.Vector3();
          obj.mesh.getWorldPosition(wp);
          wp.y += obj.size + 1.2;
          const proj = wp.clone().project(cameraRef.current);
          if (proj.z < 1.0) {
            const cW = mountRef.current.clientWidth || 1200;
            const cH = mountRef.current.clientHeight || height;
            screenCoords.push({
              id,
              ip: obj.data.ip,
              intent: obj.data.intent || 'reconnaissance',
              riskScore: obj.data.risk_score || 0,
              riskBand: obj.data.risk_band || 'low',
              x: ((proj.x + 1) * cW) / 2,
              y: ((-proj.y + 1) * cH) / 2,
              isSelected,
              isHovered,
            });
          }
        }
      });

      setPlanetScreens(screenCoords);

      if (showEdgesRef.current) {
        edgeLinesRef.current.forEach((el) => {
          el.line.visible = true;
          const pts = [el.aObj.mesh.position.clone(), el.bObj.mesh.position.clone()];
          el.line.geometry.setFromPoints(pts);
          el.line.computeLineDistances();
        });
      } else {
        edgeLinesRef.current.forEach((el) => { el.line.visible = false; });
      }

      if (targetCameraPosRef.current) {
        const { pos, tgt } = targetCameraPosRef.current;
        camera.position.lerp(pos, 0.06);
        controls.target.lerp(tgt, 0.06);
        if (camera.position.distanceTo(pos) < 0.3) {
          targetCameraPosRef.current = null;
        }
      }

      controls.update();
      renderer.render(scene, camera);
    };
    loop();

    return () => {
      window.removeEventListener('resize', handleResize);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      planetsMapRef.current.forEach((obj) => {
        scene.remove(obj.mesh);
        obj.mesh.geometry.dispose();
        obj.mesh.material.dispose();
      });
      planetsMapRef.current.clear();
      edgeLinesRef.current.forEach((el) => scene.remove(el.line));
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [height]);

  // Sync planets with attacker data
  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;

    const planetsMap = planetsMapRef.current;
    const activeIds = new Set(displayedAttackers.map((a) => a.id));

    // Remove deleted planets
    planetsMap.forEach((obj, id) => {
      if (!activeIds.has(id)) {
        scene.remove(obj.mesh);
        if (obj.orbitLine) scene.remove(obj.orbitLine);
        obj.mesh.geometry.dispose();
        obj.mesh.material.dispose();
        planetsMap.delete(id);
      }
    });

    // Add or update planets
    displayedAttackers.forEach((atk, index) => {
      const severity = Math.min(100, Math.max(0, atk.risk_score || 20));
      const orbitRadius = 4.0 + ((100.0 - severity) / 100.0) * 13.0;
      const band = atk.risk_band || 'low';
      const bandColor = BAND_COLORS[band] || '#10b981';
      const evts = Math.max(1, atk.total_events || 1);
      const planetRadius = Math.max(0.65, Math.min(1.4, 0.65 + Math.log10(evts) * 0.38));

      let obj = planetsMap.get(atk.id);

      if (!obj) {
        const tex = createProceduralPlanetTexture(atk.intent || 'recon');
        const geo = new THREE.SphereGeometry(planetRadius, 32, 32);
        const mat = new THREE.MeshStandardMaterial({
          map: tex,
          emissive: new THREE.Color(bandColor),
          emissiveIntensity: band === 'critical' ? 0.9 : band === 'high' ? 0.7 : 0.5,
          roughness: 0.55,
          metalness: 0.2,
        });
        const mesh = new THREE.Mesh(geo, mat);

        const atmoMesh = new THREE.Mesh(
          new THREE.SphereGeometry(planetRadius * 1.18, 24, 24),
          new THREE.MeshBasicMaterial({
            color: bandColor,
            transparent: true,
            opacity: 0.22,
            blending: THREE.AdditiveBlending,
            side: THREE.BackSide,
          })
        );
        mesh.add(atmoMesh);

        const total = Math.max(1, displayedAttackers.length);
        const initialAngle = (index / total) * Math.PI * 2 + Math.random() * 0.5;
        const orbitPts = [];
        for (let s = 0; s <= 128; s++) {
          const t = (s / 128) * Math.PI * 2;
          orbitPts.push(new THREE.Vector3(Math.cos(t) * orbitRadius, 0, Math.sin(t) * orbitRadius));
        }
        const orbitLine = new THREE.Line(
          new THREE.BufferGeometry().setFromPoints(orbitPts),
          new THREE.LineBasicMaterial({ color: bandColor, transparent: true, opacity: band === 'critical' ? 0.5 : 0.22 })
        );

        scene.add(mesh);
        scene.add(orbitLine);

        obj = {
          mesh,
          atmo: atmoMesh,
          orbitLine,
          orbitRadius,
          angle: initialAngle,
          speed: (0.002 + (index % 5) * 0.0008) * (index % 2 === 0 ? 1 : -1),
          rotSpeed: 0.008 + Math.random() * 0.015,
          size: planetRadius,
          data: atk,
        };
        planetsMap.set(atk.id, obj);
      } else {
        obj.data = atk;
        obj.orbitRadius = orbitRadius;
        if (obj.mesh.material.emissive) {
          obj.mesh.material.emissive.set(bandColor);
          obj.mesh.material.emissiveIntensity = band === 'critical' ? 0.9 : band === 'high' ? 0.7 : 0.5;
        }
        if (obj.orbitLine) {
          const orbitPts = [];
          for (let s = 0; s <= 128; s++) {
            const t = (s / 128) * Math.PI * 2;
            orbitPts.push(new THREE.Vector3(Math.cos(t) * orbitRadius, 0, Math.sin(t) * orbitRadius));
          }
          obj.orbitLine.geometry.setFromPoints(orbitPts);
        }
      }
    });
  }, [displayedAttackers]);

  // Sync correlation edges
  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;

    edgeLinesRef.current.forEach((el) => scene.remove(el.line));
    edgeLinesRef.current = [];

    if (!showRelationships || !relationships || relationships.length === 0) return;

    relationships.forEach((rel) => {
      const aObj = planetsMapRef.current.get(rel.attacker_a_id);
      const bObj = planetsMapRef.current.get(rel.attacker_b_id);
      if (!aObj || !bObj) return;

      const edgeColor = EDGE_COLORS[rel.relationship_type] || EDGE_COLORS[rel.rel_type] || '#00f0ff';
      const edgeMat = new THREE.LineDashedMaterial({
        color: edgeColor,
        dashSize: 0.6,
        gapSize: 0.3,
        transparent: true,
        opacity: 0.7,
      });
      const edgeGeo = new THREE.BufferGeometry().setFromPoints([
        aObj.mesh.position.clone(),
        bObj.mesh.position.clone(),
      ]);
      const edgeLine = new THREE.Line(edgeGeo, edgeMat);
      edgeLine.computeLineDistances();
      scene.add(edgeLine);
      edgeLinesRef.current.push({ line: edgeLine, aObj, bObj, rel });
    });
  }, [relationships, showRelationships, displayedAttackers]);

  // Handle Raycasting click on planets
  const handleCanvasClick = useCallback((e) => {
    const container = mountRef.current;
    const camera = cameraRef.current;
    const scene = sceneRef.current;
    if (!container || !camera || !scene) return;

    const rect = container.getBoundingClientRect();
    const mouse = new THREE.Vector2(
      ((e.clientX - rect.left) / container.clientWidth) * 2 - 1,
      -((e.clientY - rect.top) / container.clientHeight) * 2 + 1
    );

    const raycaster = new THREE.Raycaster();
    raycaster.setFromCamera(mouse, camera);

    const meshes = [];
    const idMap = new Map();
    planetsMapRef.current.forEach((obj, id) => {
      meshes.push(obj.mesh);
      idMap.set(obj.mesh.uuid, id);
    });

    const hits = raycaster.intersectObjects(meshes, false);
    if (hits.length > 0) {
      const hitId = idMap.get(hits[0].object.uuid);
      if (hitId) {
        setSelectedAttackerId(hitId);
        const obj = planetsMapRef.current.get(hitId);
        if (obj) {
          const wp = new THREE.Vector3();
          obj.mesh.getWorldPosition(wp);
          targetCameraPosRef.current = {
            pos: new THREE.Vector3(wp.x * 1.35, wp.y + 4.5, wp.z * 1.35 + 9),
            tgt: wp.clone(),
          };
        }
      }
    }
  }, [setSelectedAttackerId]);

  // Reset Camera View
  const handleResetCamera = useCallback(() => {
    targetCameraPosRef.current = {
      pos: new THREE.Vector3(0, 24, 46),
      tgt: new THREE.Vector3(0, 0, 0),
    };
  }, []);

  const containerHeight = isPreview ? 400 : height;

  return (
    <div
      className="relative w-full rounded border border-cyan-500/30 bg-black/95 overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.9)] flex"
      style={{ height: `${containerHeight}px` }}
    >
      {/* Left Sidebar — Attacker List */}
      <div className="w-52 h-full flex flex-col border-r border-soc-border bg-soc-surface/90 backdrop-blur z-10 font-mono text-xs shrink-0">
        <div className="p-2 border-b border-soc-border space-y-1.5">
          <div className="flex items-center justify-between text-soc-muted text-[10px] uppercase font-bold tracking-wider">
            <span>ORBITAL ENTITIES</span>
            <span className="text-cyan-400 font-bold">{displayedAttackers.length}</span>
          </div>
          <div className="relative">
            <Search className="h-3 w-3 text-soc-muted absolute left-2 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter IP / intent..."
              className="w-full bg-black/60 border border-soc-border rounded pl-6 pr-2 py-0.5 text-white text-[11px] focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-1 space-y-0.5">
          {displayedAttackers.map((atk) => {
            const isSelected = selectedAttackerId === atk.id;
            const color = BAND_COLORS[atk.risk_band] || '#10b981';
            return (
              <div
                key={atk.id}
                onClick={() => {
                  setSelectedAttackerId(atk.id);
                  const obj = planetsMapRef.current.get(atk.id);
                  if (obj) {
                    const wp = new THREE.Vector3();
                    obj.mesh.getWorldPosition(wp);
                    targetCameraPosRef.current = {
                      pos: new THREE.Vector3(wp.x * 1.35, wp.y + 4.5, wp.z * 1.35 + 9),
                      tgt: wp.clone(),
                    };
                  }
                }}
                className={`p-1.5 rounded cursor-pointer flex items-center justify-between border transition ${
                  isSelected
                    ? 'bg-cyan-950/60 border-cyan-400 text-white'
                    : 'bg-soc-card/40 border-soc-border/40 hover:border-cyan-500/40 text-soc-muted hover:text-white'
                }`}
              >
                <div className="flex items-center space-x-1.5 min-w-0">
                  <span className="h-2 w-2 rounded-full shrink-0 shadow" style={{ backgroundColor: color }} />
                  <div className="min-w-0">
                    <div className="font-bold text-[11px] truncate">{atk.ip}</div>
                    <div className="text-[9px] text-soc-muted truncate">{atk.intent || 'recon'}</div>
                  </div>
                </div>
                <div className="text-[10px] font-bold shrink-0" style={{ color }}>
                  {(atk.risk_score || 0).toFixed(0)}
                </div>
              </div>
            );
          })}
          {displayedAttackers.length === 0 && (
            <div className="text-center text-soc-muted text-[11px] py-6">No threats detected</div>
          )}
        </div>
      </div>

      {/* 3D Canvas Viewport */}
      <div className="relative flex-1 h-full">
        <div
          ref={mountRef}
          onClick={handleCanvasClick}
          onDoubleClick={handleResetCamera}
          className="w-full h-full cursor-grab active:cursor-grabbing"
        />

        {/* Floating 3D HUD Labels */}
        {showLabels && (
          <div className="absolute inset-0 pointer-events-none overflow-hidden">
            {planetScreens.map((lbl) => {
              const isCrit = lbl.riskBand === 'critical';
              const isHigh = lbl.riskBand === 'high';
              return (
                <div
                  key={lbl.id}
                  className={`absolute transition-all duration-75 pointer-events-auto cursor-pointer ${
                    lbl.isSelected ? 'z-30 scale-110' : lbl.isHovered ? 'z-20 scale-105' : 'z-10'
                  }`}
                  style={{ transform: `translate(${lbl.x}px,${lbl.y}px) translate(-50%,-100%)` }}
                  onClick={() => setSelectedAttackerId(lbl.id)}
                  onMouseEnter={() => setHoveredPlanetId(lbl.id)}
                  onMouseLeave={() => setHoveredPlanetId(null)}
                >
                  <div
                    className={`px-2 py-1 rounded bg-black/85 backdrop-blur-md border font-mono text-[10px] shadow-lg flex flex-col space-y-0.5 transition-all ${
                      lbl.isSelected
                        ? 'border-cyan-400 text-white shadow-[0_0_18px_rgba(0,240,255,0.6)] ring-1 ring-cyan-400'
                        : isCrit
                        ? 'border-red-500/70 text-red-200'
                        : isHigh
                        ? 'border-orange-500/70 text-orange-200'
                        : 'border-cyan-500/35 text-cyan-200'
                    }`}
                  >
                    <div className="flex items-center space-x-1.5 font-bold">
                      <span
                        className={`h-1.5 w-1.5 rounded-full animate-pulse ${
                          isCrit ? 'bg-red-400' : isHigh ? 'bg-orange-400' : 'bg-emerald-400'
                        }`}
                      />
                      <span>{lbl.ip}</span>
                    </div>
                    <div className="flex items-center justify-between text-[9px] text-soc-muted">
                      <span className="uppercase">{lbl.riskBand}</span>
                      <span
                        className={
                          isCrit ? 'text-red-400 font-bold' : isHigh ? 'text-orange-400 font-bold' : 'text-emerald-400'
                        }
                      >
                        {lbl.riskScore.toFixed(0)}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Top-left: Title HUD */}
        <div className="absolute top-3 left-3 z-20 pointer-events-none">
          <div className="p-2.5 rounded bg-black/80 backdrop-blur-md border border-cyan-500/40 font-mono shadow-xl">
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
              <h1 className="text-sm font-bold tracking-widest text-white uppercase">THREAT UNIVERSE</h1>
            </div>
            <p className="text-[10px] text-cyan-300/80 uppercase tracking-wider mt-0.5">
              CYBERSECURITY 3D COMMAND CENTER
            </p>
          </div>
        </div>

        {/* Top-right: Dynamic Clock */}
        <div className="absolute top-3 right-3 z-20 pointer-events-none text-right font-mono hidden sm:block">
          <div className="p-2.5 rounded bg-black/80 backdrop-blur-md border border-cyan-500/40 shadow-xl">
            <div className="text-xs font-bold text-white tracking-wider">LIVE THREAT MONITORING</div>
            <div className="text-[10px] text-cyan-400 tracking-wide mt-0.5">REAL-TIME NETWORK ANALYSIS</div>
            <div className="text-[10px] text-soc-muted mt-1 border-t border-gray-800 pt-1">{clockTime}</div>
          </div>
        </div>

        {/* Top-center: Controls Bar */}
        <div className="absolute top-3 left-1/2 -translate-x-1/2 z-20 flex items-center space-x-1 p-1 rounded bg-black/80 backdrop-blur-md border border-cyan-500/30 text-xs font-mono shadow-xl">
          {['all', 'critical', 'high', 'medium', 'low'].map((band) => (
            <button
              key={band}
              onClick={() => setActiveBandFilter(band)}
              className={`px-2 py-0.5 rounded text-[10px] uppercase font-medium transition border ${
                activeBandFilter === band
                  ? 'bg-cyan-950 border-cyan-400 text-cyan-200'
                  : 'bg-soc-card/80 border-soc-border text-soc-muted hover:text-white'
              }`}
            >
              {band}
            </button>
          ))}

          <span className="text-soc-border">|</span>

          <button
            onClick={() => setShowOrbits((v) => !v)}
            title="Toggle orbit rings"
            className={`px-2 py-0.5 rounded border flex items-center space-x-1 text-[10px] transition ${
              showOrbits ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-soc-surface border-soc-border text-soc-muted'
            }`}
          >
            <Layers className="h-3 w-3" />
            <span>ORBITS</span>
          </button>

          <button
            onClick={() => setShowLabels((v) => !v)}
            title="Toggle labels"
            className={`px-2 py-0.5 rounded border flex items-center space-x-1 text-[10px] transition ${
              showLabels ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-soc-surface border-soc-border text-soc-muted'
            }`}
          >
            {showLabels ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
            <span>LABELS</span>
          </button>

          <button
            onClick={() => setShowEdges((v) => !v)}
            title="Toggle edge lines"
            className={`px-2 py-0.5 rounded border flex items-center space-x-1 text-[10px] transition ${
              showEdges ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-soc-surface border-soc-border text-soc-muted'
            }`}
          >
            <Radio className="h-3 w-3" />
            <span>EDGES ({(relationships || []).length})</span>
          </button>

          <button
            onClick={() => setIsPaused((v) => !v)}
            title="Pause/Resume orbit"
            className="px-2 py-0.5 rounded border border-soc-border bg-soc-surface text-cyan-300 hover:border-cyan-400 flex items-center space-x-1 text-[10px] transition"
          >
            {isPaused ? <Play className="h-3 w-3 text-emerald-400" /> : <Pause className="h-3 w-3 text-amber-400" />}
            <span>{isPaused ? 'RESUME' : 'PAUSE'}</span>
          </button>

          <button
            onClick={handleResetCamera}
            title="Reset camera"
            className="px-2 py-0.5 rounded border border-soc-border bg-soc-surface text-cyan-300 hover:border-cyan-400 flex items-center space-x-1 text-[10px] transition"
          >
            <RotateCcw className="h-3 w-3" />
            <span>RESET CAM</span>
          </button>

          {isPreview && onExpand && (
            <button
              onClick={onExpand}
              className="px-2 py-0.5 rounded border border-soc-border bg-soc-card text-cyan-300 hover:border-cyan-400 flex items-center space-x-1 text-[10px] transition"
            >
              <Maximize2 className="h-3 w-3" />
              <span>FULLSCREEN</span>
            </button>
          )}
        </div>

        {/* Bottom-left: Threat Summary */}
        <div className="absolute bottom-3 left-3 z-20 font-mono">
          <div className="p-2.5 rounded bg-black/85 backdrop-blur-md border border-cyan-500/40 shadow-2xl space-y-1.5 pointer-events-auto">
            <div className="text-[10px] font-bold text-soc-muted uppercase tracking-wider flex items-center justify-between border-b border-gray-800 pb-1">
              <span>THREAT SUMMARY</span>
              <span className="text-white font-bold">{threatCounts.total} TOTAL</span>
            </div>
            <div className="grid grid-cols-4 gap-1.5 text-center text-[10px]">
              {[
                { key: 'critical', label: 'CRIT', cls: 'border-red-500/30 text-red-400 hover:border-red-500', activeCls: 'bg-red-950 border-red-500 text-red-200' },
                { key: 'high', label: 'HIGH', cls: 'border-orange-500/30 text-orange-400 hover:border-orange-500', activeCls: 'bg-orange-950 border-orange-500 text-orange-200' },
                { key: 'medium', label: 'MED', cls: 'border-yellow-500/30 text-yellow-400 hover:border-yellow-500', activeCls: 'bg-yellow-950 border-yellow-500 text-yellow-200' },
                { key: 'low', label: 'LOW', cls: 'border-emerald-500/30 text-emerald-400 hover:border-emerald-500', activeCls: 'bg-emerald-950 border-emerald-500 text-emerald-200' },
              ].map(({ key, label, cls, activeCls }) => (
                <div
                  key={key}
                  onClick={() => setActiveBandFilter(activeBandFilter === key ? 'all' : key)}
                  className={`p-1.5 rounded cursor-pointer border transition bg-black/60 ${
                    activeBandFilter === key ? activeCls : cls
                  }`}
                >
                  <div className="text-[9px] uppercase">{label}</div>
                  <div className="text-xs font-bold mt-0.5">{threatCounts[key]}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom-right: Legend */}
        <div className="absolute bottom-3 right-3 z-20 font-mono hidden md:block">
          <div className="p-2.5 rounded bg-black/85 backdrop-blur-md border border-cyan-500/40 shadow-2xl">
            <div className="text-[10px] font-bold text-soc-muted uppercase tracking-wider border-b border-gray-800 pb-1 mb-1.5">
              ORBITAL TOPOLOGY
            </div>
            <div className="space-y-0.5 text-[10px]">
              <div className="flex items-center space-x-2">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                <span className="text-red-300 font-bold">CRITICAL → Inner Orbit</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="h-2 w-2 rounded-full bg-orange-500" />
                <span className="text-orange-300 font-bold">HIGH → Mid-Inner</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="h-2 w-2 rounded-full bg-yellow-500" />
                <span className="text-yellow-300 font-bold">MEDIUM → Mid-Outer</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                <span className="text-emerald-300 font-bold">LOW → Outer Orbit</span>
              </div>
            </div>
            <div className="mt-1.5 text-[9px] text-soc-muted border-t border-gray-800 pt-1 italic">
              Drag · Scroll zoom · Dbl-click reset
            </div>
          </div>
        </div>

        {/* Protected Server Center Marker */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-[70px] pointer-events-none z-10 text-center">
          <div className="px-3 py-1.5 rounded bg-black/75 backdrop-blur-md border border-amber-500/60 shadow-[0_0_20px_rgba(255,170,0,0.35)]">
            <div className="text-[10px] font-mono font-bold tracking-widest text-amber-300 flex items-center justify-center space-x-1">
              <Shield className="h-3 w-3 text-amber-400" />
              <span>PROTECTED SERVER</span>
            </div>
            <div className="text-[8px] font-mono text-soc-muted tracking-wider">CORE INFRASTRUCTURE · OPERATIONAL</div>
          </div>
        </div>
      </div>

      {/* Edge Evidence Modal */}
      {selectedEdge && (
        <div className="absolute inset-0 z-30 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md p-5 rounded-lg bg-soc-surface border-2 border-purple-500/60 shadow-[0_0_30px_rgba(168,85,247,0.4)] font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <div className="flex items-center space-x-2 text-purple-300 font-bold">
                <Share2 className="h-4 w-4" />
                <span className="uppercase">
                  {(selectedEdge.relationship_type || selectedEdge.rel_type || '').replace(/_/g, ' ')} CORRELATION
                </span>
              </div>
              <button onClick={() => setSelectedEdge(null)} className="text-soc-muted hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="flex items-center justify-between p-3 rounded bg-black/60 border border-soc-border">
              <button
                onClick={() => {
                  setSelectedAttackerId(selectedEdge.attacker_a_id);
                  setSelectedEdge(null);
                }}
                className="font-bold text-white hover:text-cyan-300 hover:underline"
              >
                {selectedEdge.attacker_a_ip}
              </button>
              <span className="text-purple-400 font-bold text-sm">↔</span>
              <button
                onClick={() => {
                  setSelectedAttackerId(selectedEdge.attacker_b_id);
                  setSelectedEdge(null);
                }}
                className="font-bold text-white hover:text-cyan-300 hover:underline"
              >
                {selectedEdge.attacker_b_ip}
              </button>
            </div>
            {selectedEdge.evidence && selectedEdge.evidence.length > 0 && (
              <div className="space-y-1">
                <div className="text-soc-muted uppercase text-[10px] font-bold tracking-wider">Evidence:</div>
                {selectedEdge.evidence.map((ev, i) => (
                  <div key={i} className="text-gray-300 text-[11px]">
                    • {ev}
                  </div>
                ))}
              </div>
            )}
            <div className="text-[10px] text-soc-muted">
              Confidence:{' '}
              <span className="text-white font-bold">{((selectedEdge.weight || 0.5) * 100).toFixed(0)}%</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
