import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SocProvider } from './context/SocContext';
import Layout from './components/Layout';
import Overview from './pages/Overview';
import LiveEvents from './pages/LiveEvents';
import AttackersPage from './pages/AttackersPage';
import UniversePage from './pages/UniversePage';
import RelationshipsPage from './pages/RelationshipsPage';
import Honeypots from './pages/Honeypots';
import IncidentsPage from './pages/IncidentsPage';
import ResponseCenterPage from './pages/ResponseCenterPage';
import ReportsPage from './pages/ReportsPage';
import FunctionIntelligencePage from './pages/FunctionIntelligencePage';
import GatewayPage from './pages/GatewayPage';
import GatewayFailuresPage from './pages/GatewayFailuresPage';

export default function App() {
  return (
    <SocProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="events" element={<LiveEvents />} />
            <Route path="gateway" element={<GatewayPage />} />
            <Route path="attackers" element={<AttackersPage />} />
            <Route path="functions" element={<FunctionIntelligencePage />} />
            <Route path="failures" element={<GatewayFailuresPage />} />
            <Route path="universe" element={<UniversePage />} />
            <Route path="relationships" element={<RelationshipsPage />} />
            <Route path="honeypots" element={<Honeypots />} />
            <Route path="incidents" element={<IncidentsPage />} />
            <Route path="response" element={<ResponseCenterPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </SocProvider>
  );
}

