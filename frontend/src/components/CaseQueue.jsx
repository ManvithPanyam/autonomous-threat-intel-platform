import React, { useState, useEffect } from 'react';
import { fetchCases } from '../api';
import { Terminal, Filter, RefreshCw, ChevronRight, AlertTriangle, Inbox } from 'lucide-react';

export default function CaseQueue({ onSelectCase, setToast }) {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [tierFilter, setTierFilter] = useState('');
  const [sortBy, setSortBy] = useState('severity_score');

  const loadCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCases(statusFilter, tierFilter);
      setCases(data);
    } catch (err) {
      setError(err.message || 'Failed to connect to backend server');
      if (setToast) {
        setToast({
          type: 'error',
          message: err.message || 'Backend unreachable. Ensure FastAPI server is running on localhost:8000.',
        });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [statusFilter, tierFilter]);

  const sortedCases = [...cases].sort((a, b) => {
    if (sortBy === 'severity_score') {
      return (b.severity_score || 0) - (a.severity_score || 0);
    } else if (sortBy === 'created_at') {
      return new Date(b.created_at || 0) - new Date(a.created_at || 0);
    }
    return 0;
  });

  const getTierBadge = (tier) => {
    const t = (tier || 'low').toLowerCase();
    switch (t) {
      case 'critical':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-extrabold bg-[#1a0808]/40 text-[#ff5555] border border-[#772222] uppercase tracking-wider">
            [CRITICAL]
          </span>
        );
      case 'high':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#1a1005]/40 text-[#ffb000] border border-[#664400] uppercase tracking-wider">
            [HIGH]
          </span>
        );
      case 'medium':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#161405]/40 text-[#eab308] border border-[#554411] uppercase tracking-wider">
            [MEDIUM]
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-semibold bg-[#0a0d0b]/40 text-[#86a397] border border-[#23332b] uppercase tracking-wider">
            [LOW]
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Header & Controls Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0b0f0d] border border-zinc-800 rounded-sm p-4 font-mono">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-[#00ff9d]" />
          <div>
            <h2 className="text-sm font-bold text-zinc-100 uppercase tracking-wide flex items-center gap-2">
              INCIDENT_QUEUE // LIVE TELEMETRY
            </h2>
            <p className="text-[11px] text-zinc-500 mt-0.5">
              Correlated security cases sorted by severity & IOC matches
            </p>
          </div>
        </div>

        {/* Filters & Sorting */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 bg-[#070b09] border border-zinc-800 rounded-sm px-2.5 py-1 text-xs text-zinc-300">
            <Filter className="w-3 h-3 text-zinc-500" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-[11px] font-mono text-zinc-200 focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-[#0b0f0d]">STATUS: ALL</option>
              <option value="open" className="bg-[#0b0f0d]">STATUS: OPEN</option>
              <option value="under_investigation" className="bg-[#0b0f0d]">STATUS: INVESTIGATING</option>
              <option value="resolved" className="bg-[#0b0f0d]">STATUS: RESOLVED</option>
            </select>
          </div>

          <div className="flex items-center gap-2 bg-[#070b09] border border-zinc-800 rounded-sm px-2.5 py-1 text-xs text-zinc-300">
            <select
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
              className="bg-transparent text-[11px] font-mono text-zinc-200 focus:outline-none cursor-pointer"
            >
              <option value="" className="bg-[#0b0f0d]">SEVERITY: ALL</option>
              <option value="critical" className="bg-[#0b0f0d]">CRITICAL ONLY</option>
              <option value="high" className="bg-[#0b0f0d]">HIGH ONLY</option>
              <option value="medium" className="bg-[#0b0f0d]">MEDIUM ONLY</option>
              <option value="low" className="bg-[#0b0f0d]">LOW ONLY</option>
            </select>
          </div>

          <div className="flex items-center gap-2 bg-[#070b09] border border-zinc-800 rounded-sm px-2.5 py-1 text-xs text-zinc-300">
            <span className="text-zinc-500 text-[11px]">SORT:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="bg-transparent text-[11px] font-mono text-zinc-200 focus:outline-none cursor-pointer font-medium"
            >
              <option value="severity_score" className="bg-[#0b0f0d]">SCORE (DESC)</option>
              <option value="created_at" className="bg-[#0b0f0d]">DATE (NEWEST)</option>
            </select>
          </div>

          <button
            onClick={loadCases}
            disabled={loading}
            className="p-1.5 bg-[#101713] hover:bg-[#18241d] text-[#00ff9d] border border-zinc-800 rounded-sm transition-colors cursor-pointer"
            title="Refresh Queue"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-[#1c0b0b] border border-[#521717] rounded-sm p-3 text-rose-200 text-xs font-mono flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <div>
            <h4 className="font-bold text-rose-300 uppercase">[ERR_CONNECTION_FAILED]</h4>
            <p className="text-[11px] text-rose-300/80">{error}</p>
          </div>
        </div>
      )}

      {/* Case Table / Empty State */}
      {loading ? (
        <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-12 text-center text-zinc-500 font-mono">
          <div className="inline-flex items-center gap-2 text-xs text-[#00ff9d]">
            <RefreshCw className="w-4 h-4 animate-spin text-[#00ff9d]" />
            <span>FETCHING TELEMETRY CASES...</span>
            <span className="animate-cursor font-bold">_</span>
          </div>
        </div>
      ) : sortedCases.length === 0 ? (
        <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-12 text-center text-zinc-500 font-mono">
          <Inbox className="w-8 h-8 mx-auto mb-2 text-zinc-600" />
          <h3 className="text-xs font-bold text-zinc-300 uppercase tracking-wide">[NO_CASES_MATCHED]</h3>
          <p className="text-[11px] text-zinc-500 mt-1 max-w-sm mx-auto">
            Queue empty for selected criteria. Ingest new security alerts via backend ingestion API.
          </p>
        </div>
      ) : (
        <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-zinc-300">
              <thead className="bg-[#070a08] text-zinc-500 uppercase font-mono tracking-wider text-[11px] border-b border-zinc-800">
                <tr>
                  <th className="py-3 px-4 font-semibold">CASE_ID</th>
                  <th className="py-3 px-4 font-semibold">INCIDENT_TITLE</th>
                  <th className="py-3 px-4 font-semibold">SEVERITY</th>
                  <th className="py-3 px-4 font-semibold">SCORE</th>
                  <th className="py-3 px-4 font-semibold">ATT&CK TECH</th>
                  <th className="py-3 px-4 font-semibold">STATUS</th>
                  <th className="py-3 px-4 font-semibold">PENDING ACTIONS</th>
                  <th className="py-3 px-4 text-right font-semibold">INSPECT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 font-mono text-[12px]">
                {sortedCases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => onSelectCase(c.id)}
                    className="hover:bg-[#101713] cursor-pointer transition-colors group"
                  >
                    <td className="py-3 px-4 font-bold text-[#00ff9d]">#{c.id}</td>
                    <td className="py-3 px-4 font-sans font-medium text-zinc-100 max-w-xs truncate">
                      {c.title}
                    </td>
                    <td className="py-3 px-4">{getTierBadge(c.severity_tier)}</td>
                    <td className="py-3 px-4 font-extrabold text-[#00ff9d]">
                      {c.severity_score !== null ? c.severity_score : c.score}
                      <span className="text-[10px] text-zinc-600 font-normal">/100</span>
                    </td>
                    <td className="py-3 px-4">
                      {c.technique_id ? (
                        <span className="bg-[#070b09] border border-zinc-800 px-1.5 py-0.5 rounded-sm text-zinc-300 text-[11px]">
                          {c.technique_id}
                        </span>
                      ) : (
                        <span className="text-zinc-600 text-[11px]">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="uppercase px-2 py-0.5 rounded-sm bg-[#080d09] border border-zinc-800 text-zinc-400 text-[10px]">
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {c.pending_actions_count > 0 ? (
                        <span className="px-2 py-0.5 bg-[#291705] border border-[#52320b] text-[#ffb000] text-[10px] font-bold rounded-sm">
                          {c.pending_actions_count} PENDING
                        </span>
                      ) : (
                        <span className="text-zinc-600 text-[11px]">0 PENDING</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button className="p-1 bg-[#101713] group-hover:bg-[#00ff9d] group-hover:text-black text-zinc-400 rounded-sm transition-colors border border-zinc-800">
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
