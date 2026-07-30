import React from 'react';
import { Terminal, User, AlertTriangle } from 'lucide-react';

const PRESET_USERS = [
  { userId: 'analyst_alice', role: 'analyst', label: 'Analyst Alice (Full HITL Access)' },
  { userId: 'readonly_bob', role: 'readonly', label: 'Readonly Bob (View Only - 403 Enforced)' },
  { userId: 'admin_carol', role: 'admin', label: 'Admin Carol (Full HITL Access)' },
];

export default function RoleBanner({ currentUserId, currentRole, onUserChange }) {
  return (
    <div className="bg-[#0b0f0d] border-b border-zinc-800/80">
      {/* Dev Mode Banner */}
      <div className="bg-[#141006] border-b border-[#3b270a] px-4 py-1 text-[11px] text-amber-400/90 flex items-center justify-between font-mono">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
          <span>
            <strong className="text-amber-300">[SYS_ALERT] DEV/DEMO MODE:</strong> Header-based RBAC simulation active. Auth headers:{' '}
            <code className="bg-[#241a0b] px-1.5 py-0.5 rounded-sm text-amber-200 border border-amber-800/40">X-User-Role</code> &{' '}
            <code className="bg-[#241a0b] px-1.5 py-0.5 rounded-sm text-amber-200 border border-amber-800/40">X-User-ID</code>
          </span>
        </div>
        <span className="text-[10px] text-amber-500/80 uppercase tracking-widest font-bold hidden sm:inline">
          SIMULATION_ONLY
        </span>
      </div>

      {/* Primary Top Bar */}
      <header className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand Logo & Platform Title */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#0c1611] border border-[#00ff9d]/30 text-[#00ff9d] rounded-sm">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-tight text-zinc-100 font-mono flex items-center gap-2">
              AUTONOMOUS THREAT INTEL & RESPONSE PLATFORM
            </h1>
            <p className="text-[11px] text-zinc-500 font-mono">
              SOC_ORCHESTRATOR // HUMAN-IN-THE-LOOP CONTAINMENT
            </p>
          </div>
        </div>

        {/* Role Switcher & System Status */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-[#070b09] border border-zinc-800 rounded-sm text-xs font-mono text-zinc-300">
            <span className="w-2 h-2 rounded-full bg-[#00ff9d] pulse-phosphor shrink-0" />
            <span className="text-[#00ff9d] font-semibold tracking-wide text-[11px]">SOAR PIPELINE ACTIVE</span>
          </div>

          <div className="flex items-center gap-2 bg-[#070b09] border border-zinc-800 rounded-sm px-2.5 py-1 font-mono text-xs">
            <User className="w-3.5 h-3.5 text-[#00ff9d]" />
            <span className="text-zinc-500 text-[11px] hidden sm:inline">USER:</span>
            <select
              value={`${currentUserId}:${currentRole}`}
              onChange={(e) => {
                const [uid, r] = e.target.value.split(':');
                onUserChange(uid, r);
              }}
              className="bg-transparent text-xs font-mono text-zinc-200 focus:outline-none cursor-pointer pr-1"
            >
              {PRESET_USERS.map((u) => (
                <option key={u.userId} value={`${u.userId}:${u.role}`} className="bg-[#0b0f0d] text-zinc-200">
                  {u.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </header>
    </div>
  );
}
