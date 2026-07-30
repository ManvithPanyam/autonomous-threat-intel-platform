import React, { useEffect } from 'react';
import { Terminal, AlertTriangle, XCircle, X } from 'lucide-react';

export default function Toast({ toast, onClose }) {
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => {
      onClose();
    }, 6000);
    return () => clearTimeout(timer);
  }, [toast, onClose]);

  if (!toast) return null;

  const isSuccess = toast.type === 'success';
  const isConflict = toast.type === 'conflict';
  const isForbidden = toast.type === 'forbidden';
  const isError = toast.type === 'error';

  let borderClass = 'border-zinc-700 bg-[#050806] text-zinc-100';
  let icon = <Terminal className="w-4 h-4 text-[#00ff9d] shrink-0" />;
  let title = '[SYS_NOTIFY] ACTION_COMPLETED';
  let titleColor = 'text-[#00ff9d]';

  if (isSuccess) {
    borderClass = 'border-[#00ff9d]/70 bg-[#040d08] text-zinc-100 shadow-[0_0_15px_rgba(0,255,157,0.15)]';
    title = '[SYS_SUCCESS] ACTION_COMPLETED';
    titleColor = 'text-[#00ff9d]';
  } else if (isConflict) {
    borderClass = 'border-amber-500/80 bg-[#140e05] text-zinc-100 shadow-[0_0_15px_rgba(255,176,0,0.15)]';
    icon = <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
    title = '[409_CONFLICT] CONCURRENT_MUTATION';
    titleColor = 'text-amber-400';
  } else if (isForbidden) {
    borderClass = 'border-rose-500/80 bg-[#170606] text-zinc-100 shadow-[0_0_15px_rgba(244,63,94,0.15)]';
    icon = <XCircle className="w-4 h-4 text-rose-400 shrink-0" />;
    title = '[403_FORBIDDEN] RBAC_GUARD_ENFORCED';
    titleColor = 'text-rose-400';
  } else if (isError) {
    borderClass = 'border-rose-600 bg-[#170606] text-zinc-100 shadow-[0_0_15px_rgba(244,63,94,0.15)]';
    icon = <XCircle className="w-4 h-4 text-rose-400 shrink-0" />;
    title = '[SYS_ERROR] TASK_FAILED';
    titleColor = 'text-rose-400';
  }

  return (
    <div className="fixed bottom-5 right-5 z-[100] max-w-md w-full font-mono transition-all duration-200 ease-out">
      <div className={`p-3.5 rounded-sm border shadow-2xl flex items-start gap-3 ${borderClass}`}>
        <div className="mt-0.5">{icon}</div>
        <div className="flex-1 min-w-0">
          <h4 className={`text-xs font-bold uppercase tracking-wide ${titleColor}`}>{title}</h4>
          <p className="text-[11px] text-zinc-200 mt-1 leading-relaxed">{toast.message}</p>
        </div>
        <button
          onClick={onClose}
          className="text-zinc-500 hover:text-zinc-100 p-1 rounded-sm transition-colors cursor-pointer"
          title="Dismiss notification"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
