import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import {
  Share2,
  Link2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  Shield,
  Server,
  Terminal,
  Globe,
  Info,
  X,
  ChevronRight,
} from 'lucide-react';
import { useSoc } from '../context/SocContext';

const NODE_COLORS = {
  attacker: {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#10b981',
  },
  honeypot: '#00f0ff',
  url: '#a855f7',
};

const EDGE_COLORS = {
  same_fingerprint: '#00f0ff',
  shared_credentials: '#a855f7',
  shared_malware: '#ef4444',
  same_honeypot_window: '#eab308',
  accessed: '#64748b',
};

export default function RelationshipsPage() {
  const { relationships = [], attackers = [], honeypots = [], setSelectedAttackerId } = useSoc();
  const canvasRef = useRef(null);
  const containerRef = useRef(null);

  const [selectedEdgeType, setSelectedEdgeType] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [hoveredNode, setHoveredNode] = useState(null);

  // Performance refs to prevent animation tear-down on mouse moves
  const hoveredNodeRef = useRef(null);
  hoveredNodeRef.current = hoveredNode;
  const selectedEdgeTypeRef = useRef(selectedEdgeType);
  selectedEdgeTypeRef.current = selectedEdgeType;
  const searchTermRef = useRef(searchTerm);
  searchTermRef.current = searchTerm;

  // Zoom and pan
  const [transform, setTransform] = useState({ scale: 1.0, offsetX: 0, offsetY: 0 });
  const transformRef = useRef(transform);
  transformRef.current = transform;

  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const draggedNodeRef = useRef(null);

  // Simulation physics thermal energy (decays to 0 when settled to free CPU)
  const alphaRef = useRef(1.0);

  // Simulation graph model
  const graphRef = useRef({
    nodes: [],
    edges: [],
  });

  // Build Graph Nodes & Edges from real SOC state
  useEffect(() => {
    const nodes = [];
    const edges = [];
    const nodeMap = new Map();

    const atks = Array.isArray(attackers) ? attackers : [];
    const rels = Array.isArray(relationships) ? relationships : [];
    const numAtks = Math.max(1, atks.length);

    // 1. Attacker Nodes
    atks.forEach((atk, idx) => {
      const angle = (idx / numAtks) * Math.PI * 2;
      const node = {
        id: `atk-${atk.id}`,
        type: 'attacker',
        label: atk.ip || `Attacker #${atk.id}`,
        data: atk,
        radius: 12 + Math.min(8, (atk.total_events || 1) / 5),
        color: NODE_COLORS.attacker[atk.risk_band] || '#10b981',
        x: 450 + Math.cos(angle) * 220,
        y: 300 + Math.sin(angle) * 200,
        vx: 0,
        vy: 0,
        fixed: false,
      };
      nodes.push(node);
      nodeMap.set(`atk-${atk.id}`, node);
      if (atk.ip) nodeMap.set(atk.ip, node);
    });

    // 2. Honeypot Decoy Nodes
    const hpList = ['cowrie', 'opencanary', 'dionaea', 'conpot'];
    hpList.forEach((hp, idx) => {
      const angle = (idx / hpList.length) * Math.PI * 2;
      const node = {
        id: `hp-${hp}`,
        type: 'honeypot',
        label: hp.toUpperCase(),
        data: { name: hp },
        radius: 18,
        color: NODE_COLORS.honeypot,
        x: 450 + Math.cos(angle) * 90,
        y: 300 + Math.sin(angle) * 90,
        vx: 0,
        vy: 0,
        fixed: true,
      };
      nodes.push(node);
      nodeMap.set(`hp-${hp}`, node);
    });

    // 3. Malware URL nodes
    atks.forEach((atk) => {
      (atk.urls || []).forEach((u) => {
        const urlId = `url-${u}`;
        if (!nodeMap.has(urlId)) {
          const urlNode = {
            id: urlId,
            type: 'url',
            label: u.length > 25 ? `${u.slice(0, 25)}...` : u,
            data: { url: u, source_ip: atk.ip },
            radius: 9,
            color: NODE_COLORS.url,
            x: 450 + (Math.random() - 0.5) * 320,
            y: 300 + (Math.random() - 0.5) * 320,
            vx: 0,
            vy: 0,
            fixed: false,
          };
          nodes.push(urlNode);
          nodeMap.set(urlId, urlNode);
        }

        const sourceNode = nodeMap.get(`atk-${atk.id}`);
        const targetNode = nodeMap.get(urlId);
        if (sourceNode && targetNode) {
          edges.push({
            source: `atk-${atk.id}`,
            target: urlId,
            sourceNode,
            targetNode,
            type: 'dropped_malware',
            weight: 0.6,
            evidence: [`Dropped weaponized payload URL: ${u}`],
          });
        }
      });
    });

    // 4. Connect Attackers to Honeypots they touched ("accessed" edges)
    atks.forEach((atk) => {
      (atk.honeypots_touched || []).forEach((hp) => {
        const targetId = `hp-${hp.toLowerCase()}`;
        const sourceNode = nodeMap.get(`atk-${atk.id}`);
        const targetNode = nodeMap.get(targetId);
        if (sourceNode && targetNode) {
          edges.push({
            source: `atk-${atk.id}`,
            target: targetId,
            sourceNode,
            targetNode,
            type: 'accessed',
            weight: 0.4,
            evidence: [`Targeted and breached deceptive sensor ${hp}`],
          });
        }
      });
    });

    // 5. Cross-Attacker Correlation Edges
    rels.forEach((rel) => {
      const srcId = `atk-${rel.attacker_a_id}`;
      const tgtId = `atk-${rel.attacker_b_id}`;
      const sourceNode = nodeMap.get(srcId);
      const targetNode = nodeMap.get(tgtId);
      if (sourceNode && targetNode) {
        edges.push({
          source: srcId,
          target: tgtId,
          sourceNode,
          targetNode,
          type: rel.rel_type,
          weight: rel.weight || 1.0,
          evidence: rel.evidence || [],
          data: rel,
        });
      }
    });

    graphRef.current = { nodes, edges };
    // Wake up physics simulation when topology changes
    alphaRef.current = 1.0;
  }, [attackers, honeypots, relationships]);

  // Spring & Force Layout Simulation Step (Smooth, cooled, and high-performance)
  useEffect(() => {
    let animId;

    const stepSimulation = () => {
      const { nodes, edges } = graphRef.current;
      const targetCenter = { x: 450, y: 310 };

      // Physics calculation only while energy is active
      if (alphaRef.current > 0.005) {
        const currentAlpha = alphaRef.current;

        // Repulsion between node pairs (bounded)
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            const n1 = nodes[i];
            const n2 = nodes[j];
            const dx = n2.x - n1.x;
            const dy = n2.y - n1.y;
            const dist = Math.max(15, Math.hypot(dx, dy));

            if (dist < 220) {
              const rawForce = ((220 - dist) / dist) * 0.06 * currentAlpha;
              const force = Math.min(6, rawForce);
              const shiftX = Math.max(-10, Math.min(10, dx * force));
              const shiftY = Math.max(-10, Math.min(10, dy * force));

              if (!n1.fixed && n1 !== draggedNodeRef.current) {
                n1.x -= shiftX;
                n1.y -= shiftY;
              }
              if (!n2.fixed && n2 !== draggedNodeRef.current) {
                n2.x += shiftX;
                n2.y += shiftY;
              }
            }
          }
        }

        // Spring attraction along edges (O(1) direct node references)
        for (let i = 0; i < edges.length; i++) {
          const edge = edges[i];
          const n1 = edge.sourceNode;
          const n2 = edge.targetNode;
          if (n1 && n2) {
            const dx = n2.x - n1.x;
            const dy = n2.y - n1.y;
            const dist = Math.max(15, Math.hypot(dx, dy));
            const desiredDist = edge.type === 'accessed' ? 120 : 160;
            const rawSpring = (dist - desiredDist) * 0.006 * (edge.weight || 0.5) * currentAlpha;
            const spring = Math.max(-8, Math.min(8, rawSpring));

            const shiftX = Math.max(-8, Math.min(8, dx * spring));
            const shiftY = Math.max(-8, Math.min(8, dy * spring));

            if (!n1.fixed && n1 !== draggedNodeRef.current) {
              n1.x += shiftX;
              n1.y += shiftY;
            }
            if (!n2.fixed && n2 !== draggedNodeRef.current) {
              n2.x -= shiftX;
              n2.y -= shiftY;
            }
          }
        }

        // Gentle centering force
        for (let i = 0; i < nodes.length; i++) {
          const n = nodes[i];
          if (!n.fixed && n !== draggedNodeRef.current) {
            n.x += (targetCenter.x - n.x) * 0.003 * currentAlpha;
            n.y += (targetCenter.y - n.y) * 0.003 * currentAlpha;
          }
        }

        // Cool down physics over time
        alphaRef.current *= 0.975;
      }

      // Render onto 2D Canvas
      const canvas = canvasRef.current;
      if (canvas) {
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        const cur = transformRef.current;
        const currentHovered = hoveredNodeRef.current;
        const currentEdgeType = selectedEdgeTypeRef.current;
        const currentSearch = (searchTermRef.current || '').trim().toLowerCase();

        ctx.fillStyle = '#06090e';
        ctx.fillRect(0, 0, width, height);

        ctx.save();
        ctx.translate(cur.offsetX, cur.offsetY);
        ctx.scale(cur.scale, cur.scale);

        // Filter visible edges
        const visibleEdges = edges.filter((e) => {
          if (currentEdgeType !== 'all' && e.type !== currentEdgeType) return false;
          return true;
        });

        // 1. Draw Edges
        visibleEdges.forEach((edge) => {
          const n1 = edge.sourceNode;
          const n2 = edge.targetNode;
          if (!n1 || !n2) return;

          const isHovered =
            currentHovered &&
            (currentHovered.id === n1.id || currentHovered.id === n2.id);

          const edgeColor = EDGE_COLORS[edge.type] || '#38bdf8';
          ctx.strokeStyle = isHovered ? edgeColor : `${edgeColor}55`;
          ctx.lineWidth = isHovered ? 2.5 : Math.max(1, (edge.weight || 0.5) * 2);
          if (edge.type === 'accessed') {
            ctx.setLineDash([3, 4]);
          } else {
            ctx.setLineDash([]);
          }

          ctx.beginPath();
          ctx.moveTo(n1.x, n1.y);
          ctx.lineTo(n2.x, n2.y);
          ctx.stroke();
          ctx.setLineDash([]);
        });

        // 2. Draw Nodes
        nodes.forEach((n) => {
          const isHovered = currentHovered?.id === n.id;
          const isSearched = currentSearch && n.label.toLowerCase().includes(currentSearch);

          // Outer halo for hovered/searched nodes
          if (isHovered || isSearched) {
            ctx.strokeStyle = '#00f0ff';
            ctx.lineWidth = 3;
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius + 5, 0, Math.PI * 2);
            ctx.stroke();
          }

          // Node body
          ctx.fillStyle = n.color;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
          ctx.fill();

          // Inner ring for honeypots
          if (n.type === 'honeypot') {
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.arc(n.x, n.y, Math.max(1, n.radius - 4), 0, Math.PI * 2);
            ctx.stroke();
          }

          // Label text
          ctx.fillStyle = isHovered || isSearched ? '#ffffff' : '#94a3b8';
          ctx.font = isHovered ? 'bold 11px JetBrains Mono, monospace' : '10px JetBrains Mono, monospace';
          ctx.textAlign = 'center';
          ctx.fillText(n.label, n.x, n.y + n.radius + 12);
        });

        ctx.restore();
      }

      animId = requestAnimationFrame(stepSimulation);
    };

    animId = requestAnimationFrame(stepSimulation);
    return () => cancelAnimationFrame(animId);
  }, []);

  // Screen to world coordinates transform
  const screenToWorld = useCallback((screenX, screenY) => {
    const cur = transformRef.current;
    return {
      x: (screenX - cur.offsetX) / cur.scale,
      y: (screenY - cur.offsetY) / cur.scale,
    };
  }, []);

  const handleMouseMove = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    if (draggedNodeRef.current) {
      const world = screenToWorld(mouseX, mouseY);
      draggedNodeRef.current.x = world.x;
      draggedNodeRef.current.y = world.y;
      alphaRef.current = Math.max(alphaRef.current, 0.4);
      return;
    }

    if (isDraggingRef.current) {
      const dx = mouseX - lastMouseRef.current.x;
      const dy = mouseY - lastMouseRef.current.y;
      lastMouseRef.current = { x: mouseX, y: mouseY };
      setTransform((prev) => ({
        ...prev,
        offsetX: prev.offsetX + dx,
        offsetY: prev.offsetY + dy,
      }));
      return;
    }

    // Hit test nodes
    const world = screenToWorld(mouseX, mouseY);
    let found = null;
    for (let i = 0; i < graphRef.current.nodes.length; i++) {
      const n = graphRef.current.nodes[i];
      if (Math.hypot(n.x - world.x, n.y - world.y) <= n.radius + 4) {
        found = n;
        break;
      }
    }

    if (found?.id !== hoveredNodeRef.current?.id) {
      setHoveredNode(found);
    }
  };

  const handleMouseDown = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const world = screenToWorld(mouseX, mouseY);
    let clickedNode = null;
    for (let i = 0; i < graphRef.current.nodes.length; i++) {
      const n = graphRef.current.nodes[i];
      if (Math.hypot(n.x - world.x, n.y - world.y) <= n.radius + 4) {
        clickedNode = n;
        break;
      }
    }

    if (clickedNode) {
      draggedNodeRef.current = clickedNode;
      alphaRef.current = Math.max(alphaRef.current, 0.6);
    } else {
      isDraggingRef.current = true;
      lastMouseRef.current = { x: mouseX, y: mouseY };
    }
  };

  const handleMouseUp = () => {
    draggedNodeRef.current = null;
    isDraggingRef.current = false;
  };

  const handleClick = () => {
    const node = hoveredNodeRef.current;
    if (node && node.type === 'attacker' && node.data?.id) {
      setSelectedAttackerId(node.data.id);
    }
  };

  const handleZoom = (delta) => {
    setTransform((prev) => ({
      ...prev,
      scale: Math.max(0.4, Math.min(3.0, prev.scale * (1 + delta))),
    }));
  };

  return (
    <div className="space-y-4 font-mono text-xs">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white tracking-wider flex items-center space-x-2">
            <span>FORCE-DIRECTED RELATIONSHIP GRAPH</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300 font-bold">
              {relationships.length} CAMPAIGN EDGES
            </span>
          </h1>
          <p className="text-xs text-soc-muted mt-0.5">
            Interactive topology: Drag nodes, click attacker nodes to inspect dossiers, filter edges by correlation type
          </p>
        </div>

        {/* Zoom Controls */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1 bg-soc-card border border-soc-border rounded p-0.5">
            <button
              onClick={() => handleZoom(0.25)}
              className="p-1 rounded hover:bg-soc-surface text-soc-muted hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="h-4 w-4" />
            </button>
            <button
              onClick={() => handleZoom(-0.25)}
              className="p-1 rounded hover:bg-soc-surface text-soc-muted hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="h-4 w-4" />
            </button>
            <button
              onClick={() => {
                setTransform({ scale: 1.0, offsetX: 0, offsetY: 0 });
                alphaRef.current = 1.0;
              }}
              className="p-1 rounded hover:bg-soc-surface text-soc-muted hover:text-white"
              title="Reset View"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded border border-soc-border bg-soc-card flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-[200px] relative">
          <Search className="h-3.5 w-3.5 text-soc-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search node IP, honeypot, or malware URL..."
            className="w-full bg-soc-surface border border-soc-border rounded pl-8 pr-3 py-1.5 text-white placeholder-soc-muted focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-1.5">
          <span className="text-soc-muted text-[11px] uppercase">Edge Type:</span>
          {[
            { id: 'all', label: 'ALL EDGES' },
            { id: 'same_fingerprint', label: 'FINGERPRINT' },
            { id: 'shared_credentials', label: 'CREDENTIALS' },
            { id: 'shared_malware', label: 'MALWARE' },
            { id: 'same_honeypot_window', label: 'SIMULTANEOUS' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setSelectedEdgeType(item.id);
                alphaRef.current = Math.max(alphaRef.current, 0.5);
              }}
              className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition ${
                selectedEdgeType === item.id
                  ? 'bg-cyan-950 border border-cyan-400 text-cyan-200 shadow-[0_0_8px_rgba(0,240,255,0.3)]'
                  : 'bg-soc-surface border border-soc-border text-soc-muted hover:text-white'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Interactive Canvas Area */}
      <div
        ref={containerRef}
        className="relative w-full rounded border border-soc-border bg-soc-bg overflow-hidden shadow-2xl"
        style={{ height: '620px' }}
      >
        <canvas
          ref={canvasRef}
          width={1200}
          height={620}
          onMouseMove={handleMouseMove}
          onMouseDown={handleMouseDown}
          onMouseUp={handleMouseUp}
          onClick={handleClick}
          className={`w-full h-full block ${hoveredNode ? 'cursor-pointer' : 'cursor-grab active:cursor-grabbing'}`}
        />

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-4 z-10 flex flex-wrap items-center gap-3 bg-soc-surface/90 backdrop-blur px-3 py-1.5 rounded border border-soc-border text-[10px]">
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500"></span>
            <span>CRITICAL ATTACKER</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-400"></span>
            <span>HONEYPOT DECOY</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-purple-500"></span>
            <span>MALWARE C2 URL</span>
          </div>
          <div className="text-soc-muted border-l border-soc-border pl-2.5 italic">
            Drag nodes &bull; Click to open dossier
          </div>
        </div>

        {/* Node Hover HUD */}
        {hoveredNode && (
          <div className="absolute top-4 right-4 z-20 p-3 rounded-lg bg-soc-surface/95 border border-cyan-500/60 shadow-[0_0_20px_rgba(0,240,255,0.25)] backdrop-blur max-w-xs space-y-1.5">
            <div className="flex items-center justify-between border-b border-soc-border pb-1">
              <span className="font-bold text-white text-xs">{hoveredNode.label}</span>
              <span className="text-[10px] uppercase font-bold text-cyan-400">
                {hoveredNode.type}
              </span>
            </div>
            {hoveredNode.type === 'attacker' && (
              <div className="text-[11px] text-soc-muted space-y-0.5">
                <div>
                  Risk: <span className="text-red-400 font-bold">{hoveredNode.data?.risk_score?.toFixed(0)} ({hoveredNode.data?.risk_band})</span>
                </div>
                <div>Intent: <span className="text-white capitalize">{hoveredNode.data?.intent || 'Unknown'}</span></div>
                <div>Decoys: <span className="text-cyan-300">{(hoveredNode.data?.honeypots_touched || []).join(', ') || 'None'}</span></div>
                <div className="text-cyan-400 text-[10px] pt-1 border-t border-soc-border">Click to open investigation &rarr;</div>
              </div>
            )}
            {hoveredNode.type === 'honeypot' && (
              <div className="text-[11px] text-soc-muted">
                Deception trap sensor capturing multi-port telemetry
              </div>
            )}
            {hoveredNode.type === 'url' && (
              <div className="text-[11px] text-soc-muted break-all">
                C2 dropper binary hosted at: <span className="text-purple-300">{hoveredNode.data?.url}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Correlation Matrix Evidence Cards Table */}
      <div className="space-y-3 pt-2">
        <h3 className="font-bold text-white uppercase tracking-wider text-xs flex items-center space-x-2">
          <Link2 className="h-4 w-4 text-purple-400" />
          <span>ATTACKER CAMPAIGN CORRELATION EVIDENCE</span>
        </h3>
        {relationships.length === 0 ? (
          <div className="p-4 rounded border border-soc-border bg-soc-card text-soc-muted text-center">
            No correlated threat relationships recorded yet.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {relationships.map((rel) => (
              <div
                key={rel.id}
                className="p-3.5 rounded border border-soc-border bg-soc-card space-y-2.5 shadow-lg"
              >
                <div className="flex items-center justify-between border-b border-soc-border pb-2">
                  <span className="text-purple-300 font-bold uppercase text-xs flex items-center space-x-1.5">
                    <Share2 className="h-3.5 w-3.5" />
                    <span>{(rel.rel_type || '').replace(/_/g, ' ')}</span>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-500/40 text-purple-300 text-[10px] font-bold">
                    Weight: {((rel.weight || 0.5) * 100).toFixed(0)}%
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-soc-surface border border-soc-border">
                  <button
                    onClick={() => setSelectedAttackerId(rel.attacker_a_id)}
                    className="font-bold text-white hover:text-cyan-300 hover:underline"
                  >
                    {rel.attacker_a_ip}
                  </button>
                  <span className="text-purple-400 font-bold">&harr;</span>
                  <button
                    onClick={() => setSelectedAttackerId(rel.attacker_b_id)}
                    className="font-bold text-white hover:text-cyan-300 hover:underline"
                  >
                    {rel.attacker_b_ip}
                  </button>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] text-soc-muted uppercase">Correlated Evidence:</span>
                  <ul className="space-y-0.5 text-[11px]">
                    {(rel.evidence || []).map((ev, i) => (
                      <li key={i} className="text-gray-300 flex items-start space-x-1.5">
                        <span className="text-purple-400">&bull;</span>
                        <span>{ev}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
