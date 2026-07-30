import React from 'react';
import ReactMarkdown from 'react-markdown';
import { Terminal, AlertTriangle, Bot } from 'lucide-react';

export default function AISummaryCard({ summary }) {
  if (!summary) {
    return (
      <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm p-6 text-center font-mono">
        <Bot className="w-6 h-6 text-zinc-600 mx-auto mb-2 animate-pulse" />
        <h4 className="text-xs font-bold text-zinc-400 uppercase">[AI_SYNTHESIS_PENDING]</h4>
        <p className="text-[11px] text-zinc-500 mt-1">
          Gemini LLM summarizer engine is processing telemetry for this incident...
        </p>
      </div>
    );
  }

  return (
    <div className="bg-[#0b0f0d] border border-zinc-700/80 rounded-sm overflow-hidden shadow-2xl">
      {/* Visual Disclaimer Banner */}
      <div className="bg-[#070a08] border-b border-zinc-800 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 font-mono">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#00ff9d]" />
          <span className="text-xs font-bold text-zinc-200 uppercase tracking-wide">
            [AI_INCIDENT_SYNTHESIS]
          </span>
        </div>

        <div className="flex items-center gap-1.5 px-2.5 py-0.5 bg-[#171206] border border-[#47340c] rounded-sm text-[10px] font-mono text-amber-400">
          <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
          <span>AI-GENERATED // HUMAN REVIEW REQUIRED</span>
        </div>
      </div>

      {/* Markdown Content (Sans-Serif Prose for Maximum Legibility) */}
      <div className="p-5 font-sans text-zinc-300 text-xs leading-relaxed prose prose-invert max-w-none prose-headings:font-mono prose-headings:text-zinc-100 prose-headings:text-sm prose-strong:text-zinc-100 prose-code:font-mono prose-code:text-[#00ff9d] prose-code:bg-[#050806] prose-code:px-1.5 prose-code:py-0.5 prose-code:border prose-code:border-zinc-800 prose-code:rounded-sm">
        <ReactMarkdown>{summary}</ReactMarkdown>
      </div>
    </div>
  );
}
