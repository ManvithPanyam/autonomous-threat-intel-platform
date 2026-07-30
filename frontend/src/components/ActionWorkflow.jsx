import React, { useState, useEffect } from 'react';
import { approveAction, denyAction } from '../api';
import { Terminal, Check, X, Clock, Loader2, Info } from 'lucide-react';

export default function ActionWorkflow({ caseId, actions: initialActions, onActionUpdated, setToast }) {
  const [actions, setActions] = useState(initialActions || []);
  const [denyingActionId, setDenyingActionId] = useState(null);
  const [denialReason, setDenialReason] = useState('');
  const [loadingActionId, setLoadingActionId] = useState(null);

  useEffect(() => {
    setActions(initialActions || []);
  }, [initialActions]);

  // Poll for status updates if any action is approved or executing
  useEffect(() => {
    const hasNonTerminal = actions.some((a) => a.status === 'approved' || a.status === 'executing');
    if (!hasNonTerminal) return;

    const interval = setInterval(() => {
      onActionUpdated();
    }, 2500);

    return () => clearInterval(interval);
  }, [actions, onActionUpdated]);

  const handleApprove = async (actionId) => {
    setLoadingActionId(actionId);
    try {
      const updatedAction = await approveAction(actionId);
      setToast({
        type: 'success',
        message: `Action #${actionId} (${updatedAction.action_type}) approved! Dispatched background execution task.`,
      });
      onActionUpdated();
    } catch (err) {
      if (err.status === 409) {
        setToast({
          type: 'conflict',
          message: err.detail || `Action #${actionId} was already approved/denied by another analyst!`,
        });
      } else if (err.status === 403) {
        setToast({
          type: 'forbidden',
          message: err.detail || 'Forbidden: Readonly role cannot approve containment actions.',
        });
      } else {
        setToast({
          type: 'error',
          message: err.message || 'Failed to approve containment action.',
        });
      }
      onActionUpdated();
    } finally {
      setLoadingActionId(null);
    }
  };

  const handleDenySubmit = async (e) => {
    e.preventDefault();
    if (!denialReason.trim()) return;

    const actionId = denyingActionId;
    setLoadingActionId(actionId);
    try {
      const updatedAction = await denyAction(actionId, denialReason);
      setToast({
        type: 'success',
        message: `Action #${actionId} (${updatedAction.action_type}) denied. Reason recorded.`,
      });
      setDenyingActionId(null);
      setDenialReason('');
      onActionUpdated();
    } catch (err) {
      if (err.status === 409) {
        setToast({
          type: 'conflict',
          message: err.detail || `Action #${actionId} was already approved/denied by another analyst!`,
        });
      } else if (err.status === 403) {
        setToast({
          type: 'forbidden',
          message: err.detail || 'Forbidden: Readonly role cannot deny containment actions.',
        });
      } else {
        setToast({
          type: 'error',
          message: err.message || 'Failed to deny containment action.',
        });
      }
      onActionUpdated();
    } finally {
      setLoadingActionId(null);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'pending':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#261905] text-[#ffb000] border border-[#52350b] flex items-center gap-1.5 w-fit">
            <Clock className="w-3 h-3 text-[#ffb000]" /> [PENDING_ANALYST_REVIEW]
          </span>
        );
      case 'approved':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#0a1b24] text-cyan-300 border border-[#143e52] flex items-center gap-1.5 w-fit">
            <Loader2 className="w-3 h-3 animate-spin text-cyan-400" /> [APPROVED_QUEUED]
          </span>
        );
      case 'executing':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#1b0a24] text-purple-300 border border-[#3e1452] flex items-center gap-1.5 w-fit">
            <Loader2 className="w-3 h-3 animate-spin text-purple-400" /> [EXECUTING_TASK]
          </span>
        );
      case 'executed':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#091f14] text-[#00ff9d] border border-[#14472d] flex items-center gap-1.5 w-fit">
            <Check className="w-3 h-3 text-[#00ff9d]" /> [EXECUTED_TERMINAL]
          </span>
        );
      case 'denied':
        return (
          <span className="px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold bg-[#260a0a] text-rose-300 border border-[#521414] flex items-center gap-1.5 w-fit">
            <X className="w-3 h-3 text-rose-400" /> [DENIED_TERMINAL]
          </span>
        );
      default:
        return <span className="text-[11px] font-mono text-zinc-500">[{status}]</span>;
    }
  };

  return (
    <div className="bg-[#0b0f0d] border border-zinc-800 rounded-sm overflow-hidden font-mono shadow-2xl">
      <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#00ff9d]" />
          <h3 className="text-xs font-bold text-zinc-200 uppercase tracking-wide">
            CONTAINMENT_RESPONSE_CONSOLE
          </h3>
        </div>
        <span className="text-[10px] text-zinc-500">
          HITL WORKFLOW // ENFORCED RBAC
        </span>
      </div>

      <div className="p-4">
        {actions.length === 0 ? (
          <div className="text-center py-6 text-zinc-500">
            <Info className="w-5 h-5 mx-auto mb-1 text-zinc-600" />
            <p className="text-[11px]">No containment actions generated for this case.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {actions.map((act) => {
              const isPending = act.status === 'pending';
              const isLoading = loadingActionId === act.id;

              return (
                <div
                  key={act.id}
                  className="bg-[#060907] border border-zinc-800/80 rounded-sm p-4 hover:border-zinc-700 transition-all"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2.5">
                        <span className="text-xs font-bold text-[#00ff9d]">
                          {act.action_type}
                        </span>
                        {getStatusBadge(act.status)}
                      </div>
                      <p className="text-[11px] text-zinc-400 mt-1.5">
                        TARGET: <span className="text-zinc-200 font-semibold">{act.target}</span>
                      </p>
                    </div>

                    {/* Approve / Deny Action Buttons (Weighty HITL Approval Gate) */}
                    {isPending && (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleApprove(act.id)}
                          disabled={isLoading}
                          className="px-3.5 py-1.5 bg-[#0f291e] hover:bg-[#163b2c] disabled:opacity-50 text-[#00ff9d] border border-[#00ff9d]/60 font-mono font-extrabold text-xs rounded-sm transition-all flex items-center gap-1.5 cursor-pointer shadow-md shadow-[#00ff9d]/10"
                        >
                          {isLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                          [ APPROVE ACTION ]
                        </button>

                        <button
                          onClick={() => setDenyingActionId(act.id)}
                          disabled={isLoading}
                          className="px-3.5 py-1.5 bg-[#260d0d] hover:bg-[#3d1414] border border-rose-800/80 hover:border-rose-600 text-rose-300 font-mono font-bold text-xs rounded-sm transition-all flex items-center gap-1.5 cursor-pointer"
                        >
                          <X className="w-3.5 h-3.5 text-rose-400" />
                          [ DENY ACTION ]
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Execution Results / Denial Details */}
                  {act.mock_result && (
                    <div className="mt-3 p-2.5 bg-[#0b0f0d] border border-zinc-800 rounded-sm">
                      <span className="text-[10px] text-zinc-500 uppercase tracking-wider block mb-1">
                        MOCK_HANDLER_RESULT:
                      </span>
                      <pre className="text-[11px] text-[#00ff9d] overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(act.mock_result, null, 2)}
                      </pre>
                    </div>
                  )}

                  {act.denial_reason && (
                    <div className="mt-3 p-2.5 bg-[#1f0d0d] border border-[#4d1f1f] rounded-sm text-[11px] text-rose-200">
                      <span className="font-bold text-rose-300">DENIAL_REASON:</span> {act.denial_reason}
                    </div>
                  )}

                  {act.operator_id && (
                    <p className="text-[10px] text-zinc-600 mt-2">
                      OPERATOR: {act.operator_id} ({act.operator_email})
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Denial Reason Modal */}
      {denyingActionId && (
        <div className="fixed inset-0 z-50 bg-[#040605]/85 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-[#0b0f0d] border border-zinc-700 rounded-sm max-w-md w-full p-5 font-mono shadow-2xl">
            <h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wide mb-2 text-[#00ff9d]">
              [DENY_ACTION_PROMPT] ACTION #{denyingActionId}
            </h3>
            <p className="text-[11px] text-zinc-400 mb-4 font-sans">
              Provide mandatory technical justification for denying this containment action. Reason will be recorded in audit log.
            </p>

            <form onSubmit={handleDenySubmit}>
              <textarea
                value={denialReason}
                onChange={(e) => setDenialReason(e.target.value)}
                placeholder="e.g. Host is critical domain controller; manual isolation required."
                rows={3}
                required
                className="w-full bg-[#060907] border border-zinc-800 rounded-sm p-2.5 text-xs text-zinc-200 focus:outline-none focus:border-rose-500 mb-4 font-mono"
              />

              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setDenyingActionId(null);
                    setDenialReason('');
                  }}
                  className="px-3 py-1.5 text-xs font-bold text-zinc-500 hover:text-zinc-200 cursor-pointer"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 bg-[#260d0d] hover:bg-[#3d1414] border border-rose-600 text-rose-200 font-bold text-xs rounded-sm transition-colors cursor-pointer"
                >
                  CONFIRM DENIAL
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
