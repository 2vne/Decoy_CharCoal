import React, { useState, useEffect } from 'react';
import PortalLayout from './PortalLayout';
import PortalLogin from './PortalLogin';
import PortalOtp from './PortalOtp';
import PortalDashboard from './PortalDashboard';
import PortalCustomers from './PortalCustomers';
import PortalAdmin from './PortalAdmin';
import PortalBilling from './PortalBilling';
import PortalPasswordReset from './PortalPasswordReset';

export default function PortalApp({ initialMode = 'decoy' }) {
  // Mode determines whether requests go to /demo/decoy or /demo/real
  const [basePath, setBasePath] = useState(
    initialMode === 'real' ? '/demo/real' : '/demo/decoy'
  );

  // Authentication & Flow State
  const [user, setUser] = useState(() => {
    try {
      const saved = sessionStorage.getItem('sentinel_portal_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [authStep, setAuthStep] = useState(() => {
    try {
      const saved = sessionStorage.getItem('sentinel_portal_user');
      return saved ? 'authenticated' : 'login';
    } catch {
      return 'login';
    }
  });

  const [pendingLogin, setPendingLogin] = useState(null);
  const [currentTab, setCurrentTab] = useState('dashboard');

  const handleLoginSuccess = (loginData) => {
    if (loginData.requiresOtp) {
      setPendingLogin(loginData);
      setAuthStep('otp');
    } else {
      const authUser = {
        email: loginData.email,
        sessionToken: loginData.sessionToken,
        role: 'operator',
        user: loginData.email.split('@')[0],
      };
      setUser(authUser);
      sessionStorage.setItem('sentinel_portal_user', JSON.stringify(authUser));
      setAuthStep('authenticated');
      setCurrentTab('dashboard');
    }
  };

  const handleOtpSuccess = (otpData) => {
    const authUser = {
      email: otpData.email,
      sessionToken: pendingLogin?.sessionToken || `sess_${Date.now()}`,
      role: otpData.role || 'administrator',
      user: otpData.user || otpData.email.split('@')[0],
      appScope: otpData.appScope,
    };
    setUser(authUser);
    sessionStorage.setItem('sentinel_portal_user', JSON.stringify(authUser));
    setAuthStep('authenticated');
    setCurrentTab('dashboard');
  };

  const handleLogout = () => {
    setUser(null);
    setPendingLogin(null);
    sessionStorage.removeItem('sentinel_portal_user');
    setAuthStep('login');
  };

  // Step 1: Login
  if (authStep === 'login') {
    return (
      <PortalLogin
        basePath={basePath}
        setBasePath={setBasePath}
        onLoginSuccess={handleLoginSuccess}
        onForgotPassword={() => setAuthStep('reset')}
      />
    );
  }

  // Step 2: OTP Verification
  if (authStep === 'otp') {
    return (
      <PortalOtp
        email={pendingLogin?.email || 'analyst@sentinel.local'}
        basePath={basePath}
        onVerifySuccess={handleOtpSuccess}
        onBackToLogin={() => setAuthStep('login')}
      />
    );
  }

  // Step 3: Password Reset
  if (authStep === 'reset') {
    return (
      <PortalPasswordReset
        basePath={basePath}
        onBackToLogin={() => setAuthStep('login')}
      />
    );
  }

  // Step 4: Authenticated Enterprise Portal Workspace
  return (
    <PortalLayout
      user={user}
      currentTab={currentTab}
      onTabChange={setCurrentTab}
      onLogout={handleLogout}
      basePath={basePath}
      setBasePath={setBasePath}
    >
      {currentTab === 'dashboard' && (
        <PortalDashboard
          user={user}
          basePath={basePath}
          onNavigate={(tab) => setCurrentTab(tab)}
        />
      )}

      {currentTab === 'customers' && (
        <PortalCustomers basePath={basePath} />
      )}

      {currentTab === 'admin' && (
        <PortalAdmin basePath={basePath} />
      )}

      {currentTab === 'billing' && (
        <PortalBilling basePath={basePath} />
      )}

      {currentTab === 'reset' && (
        <div className="max-w-xl mx-auto">
          <PortalPasswordReset
            basePath={basePath}
            onBackToLogin={() => setCurrentTab('dashboard')}
          />
        </div>
      )}
    </PortalLayout>
  );
}
