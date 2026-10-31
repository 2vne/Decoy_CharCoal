import React from 'react';
import ThreatUniverse from '../components/ThreatUniverse';

export default function UniversePage() {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-white tracking-wider flex items-center space-x-2">
            <span>CINEMATIC 3D THREAT UNIVERSE</span>
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping"></span>
          </h1>
          <p className="text-xs font-mono text-soc-muted mt-0.5">
            Gravitational orbital topology: High risk threats gravitate inwards toward the core protected server
          </p>
        </div>
      </div>

      <ThreatUniverse height={780} isPreview={false} />
    </div>
  );
}

