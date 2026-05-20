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

/**
 * Role-based route guard. Reads the user's role from localStorage
 * and checks against the allowedRoles list. If the user's role is
 * not in the list, redirects to dashboard (not login — they ARE authenticated).
 */
function RoleRoute({ children, allowedRoles }) {
  const user = JSON.parse(localStorage.getItem('soc_user') || '{}');
  const userRole = user.role || '';
  if (allowedRoles.includes('*') || allowedRoles.includes(userRole)) {
    return children;
  }
  return <Navigate to="/" replace />;
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
            <Route path="analytics" element={
              <RoleRoute allowedRoles={['System Administrator', 'SOC Manager', 'SOC Analyst L1', 'SOC Analyst L2']}>
                <Analytics />
              </RoleRoute>
            } />
            <Route path="mitre" element={
              <RoleRoute allowedRoles={['System Administrator', 'SOC Manager', 'SOC Analyst L1', 'SOC Analyst L2']}>
                <MitreAttack />
              </RoleRoute>
            } />
            <Route path="playbooks" element={
              <RoleRoute allowedRoles={['System Administrator', 'SOC Manager']}>
                <Playbooks />
              </RoleRoute>
            } />
            <Route path="settings" element={
              <RoleRoute allowedRoles={['System Administrator']}>
                <SettingsPage />
              </RoleRoute>
            } />
            <Route path="threatintel" element={<ThreatIntel />} />
            <Route path="audit" element={
              <RoleRoute allowedRoles={['System Administrator', 'SOC Manager']}>
                <AuditLog />
              </RoleRoute>
            } />
            <Route path="reports" element={
              <RoleRoute allowedRoles={['System Administrator', 'SOC Manager']}>
                <Reports />
              </RoleRoute>
            } />
          </Route>
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}
