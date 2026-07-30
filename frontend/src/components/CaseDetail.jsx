import React, { useState, useEffect } from 'react';
import { fetchCaseDetail } from '../api';
import AISummaryCard from './AISummaryCard';
import ActionWorkflow from './ActionWorkflow';
import { ArrowLeft, Terminal, Cpu, Database, AlertTriangle, RefreshCw, ChevronDown, ChevronUp, Layers } from 'lucide-react';

export default function CaseDetail({ caseId, onBack, setToast }) {
  const [caseData, setCaseData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedAlertId, setExpandedAlertId] = useState(null);

  const loadDetail = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCaseDetail(caseId);
      setCaseData(data);
    } catch (err) {
      setError(err.message || 'Failed to load case detail');
      if (setToast) {
        setToast({ type: 'error', message: err.message });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDetail();
  }, [caseId]);

  if (loading) {
    return (
      <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-16 text-center text-zinc-500 font-mono">
        <RefreshCw className="w-6 h-6 mx-auto mb-3 animate-spin text-[#00ff9d]" />
        <p className="text-xs text-[#00ff9d]">LOADING CONTEXT FOR CASE #{caseId}...</p>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-6 font-mono">
        <button
          onClick={onBack}
          className="mb-4 inline-flex items-center gap-2 text-xs font-bold text-[#00ff9d] hover:underline cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> &lt; BACK_TO_QUEUE
        </button>
        <div className="bg-[#1c0b0b] border border-[#521717] rounded-sm p-3 text-rose-200 text-xs flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <p>{error || 'Case object not found'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Navigation & Header Bar */}
      <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-5 font-mono">
        <button
          onClick={onBack}
          className="mb-3 inline-flex items-center gap-1.5 text-xs font-bold text-[#00ff9d] hover:text-[#00ff9d]/80 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> &lt; BACK_TO_QUEUE
        </button>

        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-lg font-extrabold text-[#00ff9d]">CASE #{caseData.id}</span>
              <span className="px-2 py-0.5 rounded-sm text-[10px] font-bold uppercase tracking-wider bg-[#070b09] text-zinc-300 border border-zinc-700">
                STATUS: {caseData.status}
              </span>
            </div>
            <h1 className="text-xl font-bold text-zinc-100 font-sans mt-1">{caseData.title}</h1>
            {caseData.description && (
              <p className="text-xs text-zinc-400 font-sans mt-1 max-w-3xl">{caseData.description}</p>
            )}
          </div>

          {/* Severity Score Card */}
          <div className="bg-[#070b09] border border-zinc-800 rounded-sm p-3 text-right min-w-[180px]">
            <span className="text-[10px] text-zinc-500 uppercase tracking-widest block mb-0.5">
              SEVERITY_SCORE
            </span>
            <div className="flex items-baseline justify-end gap-2">
              <span className="text-2xl font-black text-zinc-100">{caseData.severity_score}</span>
              <span className="text-xs font-bold font-mono text-[#00ff9d]">/100</span>
            </div>
            <span className="text-[10px] font-bold uppercase tracking-wide text-amber-400 block mt-0.5">
              TIER: {caseData.severity_tier}
            </span>
          </div>
        </div>
      </div>

      {/* Grid Layout: Left Column (AI Summary & Containment) / Right Column (Sidebar) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-4">
          {/* AI Analyst Summary */}
          <AISummaryCard summary={caseData.analyst_summary} />

          {/* Containment Response Approval Workflow */}
          <ActionWorkflow
            caseId={caseData.id}
            actions={caseData.containment_actions}
            onActionUpdated={loadDetail}
            setToast={setToast}
          />

          {/* Linked Alerts */}
          <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm overflow-hidden font-mono">
            <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#00ff9d]" />
                <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wide">
                  CORRELATED_ALERTS ({caseData.alerts?.length || 0})
                </h3>
              </div>
              <span className="text-[10px] text-zinc-500">RAW_TELEMETRY</span>
            </div>

            <div className="divide-y divide-zinc-800/60">
              {caseData.alerts?.map((alt) => (
                <div key={alt.id} className="p-4 hover:bg-[#0f1512] transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-bold text-[#00ff9d]">[{alt.source}]</span>
                        <h4 className="text-xs font-semibold text-zinc-200 font-sans">{alt.title}</h4>
                      </div>
                      <p className="text-[11px] text-zinc-400 font-sans mt-1">{alt.description}</p>
                    </div>

                    <button
                      onClick={() => setExpandedAlertId(expandedAlertId === alt.id ? null : alt.id)}
                      className="text-[11px] text-zinc-400 hover:text-[#00ff9d] flex items-center gap-1 shrink-0 cursor-pointer"
                    >
                      {expandedAlertId === alt.id ? '[-] HIDE PAYLOAD' : '[+] VIEW PAYLOAD'}
                    </button>
                  </div>

                  {expandedAlertId === alt.id && (
                    <div className="mt-3 p-3 bg-[#060907] border border-zinc-800/80 rounded-sm">
                      <pre className="text-[11px] text-zinc-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {JSON.stringify(alt.raw_payload, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column (Sidebar) */}
        <div className="space-y-4 font-mono">
          {/* MITRE ATT&CK Mapping */}
          <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-4">
            <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wide flex items-center gap-2 mb-3">
              <Cpu className="w-3.5 h-3.5 text-[#00ff9d]" />
              MITRE ATT&CK MAP
            </h3>
            {caseData.technique_id ? (
              <div className="bg-[#060907] border border-zinc-800 rounded-sm p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-[#00ff9d]">
                    {caseData.technique_id}
                  </span>
                  <span className="text-[10px] text-zinc-500">MITRE v14</span>
                </div>
                <h4 className="text-xs font-semibold text-zinc-300 font-sans">{caseData.technique_name}</h4>
              </div>
            ) : (
              <p className="text-[11px] text-zinc-600">UNMAPPED_TECHNIQUE</p>
            )}
          </div>

          {/* Dynamic Severity Score Breakdown */}
          <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-4">
            <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wide flex items-center gap-2 mb-3">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              SCORE EXPLANATION
            </h3>
            <p className="text-[11px] text-zinc-400 leading-relaxed bg-[#060907] border border-zinc-800 rounded-sm p-3">
              {caseData.severity_explanation || 'Weighted combination of MITRE base weight, VirusTotal malicious detections, AbuseIPDB confidence score, and critical asset flags.'}
            </p>
          </div>

          {/* IOCs & Threat Intel Enrichments */}
          <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-4">
            <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wide flex items-center gap-2 mb-3">
              <Database className="w-3.5 h-3.5 text-[#00ff9d]" />
              ENRICHED IOCS ({caseData.iocs?.length || 0})
            </h3>

            <div className="space-y-2.5">
              {caseData.iocs?.map((ioc) => (
                <div key={ioc.id} className="bg-[#060907] border border-zinc-800 rounded-sm p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase text-amber-400 font-bold">
                      [{ioc.ioc_type}]
                    </span>
                    <span className="text-xs font-mono font-semibold text-zinc-200">{ioc.value}</span>
                  </div>

                  {/* Enrichments summary */}
                  <div className="mt-2 text-[10px] text-zinc-400 space-y-1">
                    {ioc.enrichments?.map((e) => (
                      <div key={e.id} className="flex items-center justify-between bg-[#0b0f0d] px-2 py-0.5 border border-zinc-800/60 rounded-sm">
                        <span className="capitalize text-zinc-400">{e.source}:</span>
                        <span className="font-bold text-[#00ff9d]">
                          {e.summary_score !== null ? `SCORE: ${e.summary_score}` : e.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
