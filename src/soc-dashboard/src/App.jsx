import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { isAuthenticated } from './api';
import { ToastProvider } from './components/Toast';
import Layout from './components/Layout';
import Login from './pages/Login';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import Analytics from './pages/Analytics';
import MitreAttack from './pages/MitreAttack';
import Playbooks from './pages/Playbooks';
import SettingsPage from './pages/Settings';
import AuditLog from './pages/AuditLog';
import ThreatIntel from './pages/ThreatIntel';
import Reports from './pages/Reports';
import './index.css';

function ProtectedRoute({ children }) {
  return isAuthenticated() ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="analytics" element={<Analytics />} />
            <Route path="mitre" element={<MitreAttack />} />
            <Route path="playbooks" element={<Playbooks />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="threatintel" element={<ThreatIntel />} />
            <Route path="audit" element={<AuditLog />} />
            <Route path="reports" element={<Reports />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}

