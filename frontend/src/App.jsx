import React, { useState, useEffect } from 'react';
import RoleBanner from './components/RoleBanner';
import CaseQueue from './components/CaseQueue';
import CaseDetail from './components/CaseDetail';
import Toast from './components/Toast';

export default function App() {
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [currentUserId, setCurrentUserId] = useState(
    localStorage.getItem('user_id') || 'analyst_alice'
  );
  const [currentRole, setCurrentRole] = useState(
    localStorage.getItem('user_role') || 'analyst'
  );
  const [toast, setToast] = useState(null);

  const handleUserChange = (userId, role) => {
    setCurrentUserId(userId);
    setCurrentRole(role);
    localStorage.setItem('user_id', userId);
    localStorage.setItem('user_role', role);
    setToast({
      type: 'success',
      message: `Active identity switched to ${userId} (${role} role). Headers updated.`,
    });
  };

  return (
    <div className="min-h-screen bg-[#080c0a] text-zinc-300 flex flex-col font-sans antialiased">
      {/* Dev/Demo RBAC Header Banner */}
      <RoleBanner
        currentUserId={currentUserId}
        currentRole={currentRole}
        onUserChange={handleUserChange}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {selectedCaseId ? (
          <CaseDetail
            caseId={selectedCaseId}
            onBack={() => setSelectedCaseId(null)}
            setToast={setToast}
          />
        ) : (
          <CaseQueue
            onSelectCase={(id) => setSelectedCaseId(id)}
            setToast={setToast}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-900 bg-[#060807] py-3 px-4 text-center text-[11px] font-mono text-zinc-600 flex items-center justify-between max-w-7xl mx-auto w-full">
        <span>SOAR_SOC_CONSOLE v1.4.0 • AUTONOMOUS THREAT INTEL PLATFORM</span>
        <span className="flex items-center gap-1.5 text-zinc-500">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00ff9d]" /> ONLINE
        </span>
      </footer>

      {/* Toast Alert System */}
      <Toast toast={toast} onClose={() => setToast(null)} />
    </div>
  );
}
