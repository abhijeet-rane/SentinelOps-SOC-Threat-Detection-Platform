import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Settings as SettingsIcon, Shield, Users, Plus, X, Edit3, Trash2,
  Power, Loader, Save, KeyRound, Eye, UserPlus, ShieldPlus, Search,
  AlertTriangle, CheckCircle, Info,
} from 'lucide-react';
import { api } from '../api';
import { useToast } from '../components/ToastContext';
import MfaSection from '../components/MfaSection';

// ── Constants ──
const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.06 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };
const modalSpring = { type: 'spring', damping: 22, stiffness: 300 };

const ROLES = [
  { id: '10000000-0000-0000-0000-000000000001', name: 'SOC Analyst L1' },
  { id: '10000000-0000-0000-0000-000000000002', name: 'SOC Analyst L2' },
  { id: '10000000-0000-0000-0000-000000000003', name: 'SOC Manager' },
  { id: '10000000-0000-0000-0000-000000000004', name: 'System Administrator' },
];

const RULE_TYPES = ['Threshold', 'Correlation', 'Anomaly', 'Temporal', 'Pattern', 'ThreatIntel'];
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];

const ROLE_COLORS = {
  'System Administrator': { bg: 'rgba(139,92,246,0.15)', color: 'var(--purple-400)' },
  'SOC Manager': { bg: 'rgba(59,130,246,0.15)', color: 'var(--blue-400)' },
  'SOC Analyst L2': { bg: 'rgba(6,182,212,0.12)', color: 'var(--cyan-400)' },
  'SOC Analyst L1': { bg: 'rgba(16,185,129,0.12)', color: 'var(--green-400)' },
};

const overlayStyle = { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' };
const modalCardStyle = { width: 500, maxHeight: '80vh', overflow: 'auto' };
const labelStyle = { fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.04em' };
const infoBoxStyle = { background: 'var(--bg-deep)', padding: 10, borderRadius: 8 };
const infoLabelStyle = { fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 };
const infoValueStyle = { fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 };

const fmtDate = (d) => d ? new Date(d).toLocaleString() : '—';
const truncate = (s, n = 50) => s && s.length > n ? s.slice(0, n) + '…' : (s || '—');

// ── Reusable Modal Shell ──
function ModalShell({ open, onClose, children }) {
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          style={overlayStyle}
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.92, opacity: 0, y: 30 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.92, opacity: 0, y: 30 }}
            transition={modalSpring}
            className="card" style={modalCardStyle}
            onClick={e => e.stopPropagation()}
          >
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function ModalHeader({ title, onClose, actions }) {
  return (
    <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>{title}</h3>
      <div className="flex gap-sm items-center">
        {actions}
        <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16} /></button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// MAIN SETTINGS COMPONENT
// ══════════════════════════════════════════════════════════════════════
export default function Settings() {
  const [tab, setTab] = useState('rules');
  const toast = useToast();

  // ── Shared loading / error ──
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // ── Rules state ──
  const [rules, setRules] = useState([]);
  const [ruleModal, setRuleModal] = useState(null);       // null | 'create' | 'edit' | 'detail'
  const [selectedRule, setSelectedRule] = useState(null);
  const [ruleForm, setRuleForm] = useState(emptyRuleForm());
  const [ruleSaving, setRuleSaving] = useState(false);
  const [ruleDetailLoading, setRuleDetailLoading] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);

  // ── Users state ──
  const [users, setUsers] = useState([]);
  const [userModal, setUserModal] = useState(null);       // null | 'create' | 'edit' | 'detail'
  const [selectedUser, setSelectedUser] = useState(null);
  const [userForm, setUserForm] = useState(emptyUserForm());
  const [userSaving, setUserSaving] = useState(false);

  // ────────────────────────────────────────────────────────
  // FORM DEFAULTS
  // ────────────────────────────────────────────────────────
  function emptyRuleForm() {
    return { name: '', description: '', ruleType: 'Threshold', severity: 'Medium', mitreTechnique: '', mitreTactic: '', thresholdCount: '', timeWindowSeconds: '', ruleLogic: '', isActive: true };
  }
  function emptyUserForm() {
    return { username: '', email: '', password: '', roleId: ROLES[0].id };
  }

  // ────────────────────────────────────────────────────────
  // DATA FETCHING
  // ────────────────────────────────────────────────────────
  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getRules();
      if (res.success) setRules(res.data || []);
      else setError(res.message || 'Failed to load rules');
    } catch { setError('Failed to load rules'); }
    setLoading(false);
  }, []);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getUsers();
      if (res.success) setUsers(res.data || []);
      else setError(res.message || 'Failed to load users');
    } catch { setError('Failed to load users'); }
    setLoading(false);
  }, [setUsers, setLoading, setError]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (tab === 'rules') fetchRules();
      else if (tab === 'users') fetchUsers();
      else setLoading(false);
    }, 0);
    return () => clearTimeout(timer);
  }, [tab, fetchRules, fetchUsers]);

  // ────────────────────────────────────────────────────────
  // DETECTION RULES – ACTIONS
  // ────────────────────────────────────────────────────────
  const toggleRule = async (id, currentActive) => {
    try {
      const res = await api.toggleRule(id);
      if (res.success) {
        setRules(prev => prev.map(r => r.id === id ? { ...r, isActive: !currentActive } : r));
        toast.success(`Rule ${currentActive ? 'disabled' : 'enabled'}`);
      } else { toast.error(res.message || 'Toggle failed'); }
    } catch { toast.error('Toggle failed'); }
  };

  const deleteRule = async (id) => {
    try {
      const res = await api.deleteRule(id);
      if (res.success) {
        setRules(prev => prev.filter(r => r.id !== id));
        toast.error('Rule deleted');
      } else { toast.error(res.message || 'Delete failed'); }
    } catch { toast.error('Delete failed'); }
    setConfirmDelete(null);
  };

  const openRuleDetail = async (rule) => {
    setSelectedRule(rule);
    setRuleModal('detail');
    setRuleDetailLoading(true);
    try {
      const res = await api.getRule(rule.id);
      if (res.success && res.data) setSelectedRule(res.data);
    } catch { /* keep partial data */ }
    setRuleDetailLoading(false);
  };

  const openRuleEdit = async (rule) => {
    setRuleModal('edit');
    setRuleDetailLoading(true);
    try {
      const res = await api.getRule(rule.id);
      const d = res.success && res.data ? res.data : rule;
      setSelectedRule(d);
      setRuleForm({
        name: d.name || '', description: d.description || '',
        ruleType: d.ruleType || 'Threshold', severity: d.severity || 'Medium',
        mitreTechnique: d.mitreTechnique || '', mitreTactic: d.mitreTactic || '',
        thresholdCount: d.thresholdCount ?? '', timeWindowSeconds: d.timeWindowSeconds ?? '',
        ruleLogic: d.ruleLogic || '', isActive: d.isActive ?? true,
      });
    } catch {
      setSelectedRule(rule);
      setRuleForm({
        name: rule.name || '', description: rule.description || '',
        ruleType: rule.ruleType || 'Threshold', severity: rule.severity || 'Medium',
        mitreTechnique: rule.mitreTechnique || '', mitreTactic: rule.mitreTactic || '',
        thresholdCount: rule.thresholdCount ?? '', timeWindowSeconds: rule.timeWindowSeconds ?? '',
        ruleLogic: rule.ruleLogic || '', isActive: rule.isActive ?? true,
      });
    }
    setRuleDetailLoading(false);
  };

  const openCreateRule = () => { setRuleForm(emptyRuleForm()); setRuleModal('create'); };

  const handleSaveRule = async () => {
    if (!ruleForm.name.trim()) { toast.error('Rule name is required'); return; }
    setRuleSaving(true);
    const payload = {
      name: ruleForm.name, description: ruleForm.description,
      ruleType: ruleForm.ruleType, severity: ruleForm.severity,
      mitreTechnique: ruleForm.mitreTechnique || null,
      mitreTactic: ruleForm.mitreTactic || null,
      isActive: ruleForm.isActive,
      thresholdCount: ruleForm.thresholdCount !== '' ? parseInt(ruleForm.thresholdCount, 10) : null,
      timeWindowSeconds: ruleForm.timeWindowSeconds !== '' ? parseInt(ruleForm.timeWindowSeconds, 10) : null,
      ruleLogic: ruleForm.ruleLogic || null,
    };
    try {
      const res = ruleModal === 'create'
        ? await api.createRule(payload)
        : await api.updateRule(selectedRule.id, payload);
      if (res.success) {
        toast.success(ruleModal === 'create' ? 'Rule created' : 'Rule updated');
        setRuleModal(null);
        fetchRules();
      } else {
        toast.error(res.message || (res.errors ? res.errors.join(', ') : 'Save failed'));
      }
    } catch { toast.error('Save failed'); }
    setRuleSaving(false);
  };

  const closeRuleModal = () => { setRuleModal(null); setSelectedRule(null); };

  // ────────────────────────────────────────────────────────
  // USER MANAGEMENT – ACTIONS
  // ────────────────────────────────────────────────────────
  const openCreateUser = () => { setUserForm(emptyUserForm()); setUserModal('create'); };

  const openUserDetail = (u) => { setSelectedUser({ ...u }); setUserModal('detail'); };

  const openUserEdit = (u) => {
    setSelectedUser({ ...u });
    setUserForm({ username: u.username, email: u.email, password: '', roleId: u.roleId || ROLES.find(r => r.name === u.role)?.id || ROLES[0].id });
    setUserModal('edit');
  };

  const handleCreateUser = async () => {
    if (!userForm.username.trim() || !userForm.email.trim() || !userForm.password) {
      toast.error('All fields are required'); return;
    }
    if (userForm.password.length < 8) { toast.error('Password must be at least 8 characters'); return; }
    setUserSaving(true);
    try {
      const res = await api.register({ username: userForm.username, email: userForm.email, password: userForm.password, roleId: userForm.roleId });
      if (res.success) {
        toast.success('User created successfully');
        setUserModal(null);
        fetchUsers();
      } else {
        toast.error(res.message || (res.errors ? res.errors.join(', ') : 'Registration failed'));
      }
    } catch { toast.error('Registration failed'); }
    setUserSaving(false);
  };

  const handleUpdateUser = async () => {
    setUserSaving(true);
    try {
      const res = await api.updateUser(selectedUser.id, { email: userForm.email, roleId: userForm.roleId, isActive: selectedUser.isActive });
      if (res.success) {
        setUsers(prev => prev.map(u => u.id === selectedUser.id ? res.data : u));
        setUserModal(null);
        toast.success('User updated');
      } else { toast.error(res.message || 'Update failed'); }
    } catch { toast.error('Update failed'); }
    setUserSaving(false);
  };

  const handleDeactivateUser = async (u) => {
    try {
      const res = await api.deactivateUser(u.id);
      if (res.success) {
        setUsers(prev => prev.map(x => x.id === u.id ? { ...x, isActive: false } : x));
        if (selectedUser?.id === u.id) setSelectedUser(prev => ({ ...prev, isActive: false }));
        toast.warning('User deactivated');
      } else { toast.error(res.message || 'Deactivation failed'); }
    } catch { toast.error('Deactivation failed'); }
  };

  const handleReactivateUser = async (u) => {
    try {
      const res = await api.updateUser(u.id, { isActive: true });
      if (res.success) {
        setUsers(prev => prev.map(x => x.id === u.id ? { ...x, isActive: true } : x));
        if (selectedUser?.id === u.id) setSelectedUser(prev => ({ ...prev, isActive: true }));
        toast.success('User reactivated');
      } else { toast.error(res.message || 'Reactivation failed'); }
    } catch { toast.error('Reactivation failed'); }
  };

  const closeUserModal = () => { setUserModal(null); setSelectedUser(null); };

  // ────────────────────────────────────────────────────────
  // RENDER: Rule Form Fields (shared by Create & Edit)
  // ────────────────────────────────────────────────────────
  const renderRuleFormFields = () => (
    <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div>
        <label style={labelStyle}>Name *</label>
        <input className="form-input" value={ruleForm.name} onChange={e => setRuleForm(p => ({ ...p, name: e.target.value }))} placeholder="Rule name" />
      </div>
      <div>
        <label style={labelStyle}>Description</label>
        <textarea className="form-input" rows={3} value={ruleForm.description} onChange={e => setRuleForm(p => ({ ...p, description: e.target.value }))} placeholder="Describe the detection logic" />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          <label style={labelStyle}>Rule Type</label>
          <select className="form-select" value={ruleForm.ruleType} onChange={e => setRuleForm(p => ({ ...p, ruleType: e.target.value }))}>
            {RULE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <label style={labelStyle}>Severity</label>
          <select className="form-select" value={ruleForm.severity} onChange={e => setRuleForm(p => ({ ...p, severity: e.target.value }))}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          <label style={labelStyle}>MITRE Technique</label>
          <input className="form-input" value={ruleForm.mitreTechnique} onChange={e => setRuleForm(p => ({ ...p, mitreTechnique: e.target.value }))} placeholder="e.g. T1059.001" />
        </div>
        <div>
          <label style={labelStyle}>MITRE Tactic</label>
          <input className="form-input" value={ruleForm.mitreTactic} onChange={e => setRuleForm(p => ({ ...p, mitreTactic: e.target.value }))} placeholder="e.g. Execution" />
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          <label style={labelStyle}>Threshold Count</label>
          <input className="form-input" type="number" value={ruleForm.thresholdCount} onChange={e => setRuleForm(p => ({ ...p, thresholdCount: e.target.value }))} placeholder="Optional" />
        </div>
        <div>
          <label style={labelStyle}>Time Window (sec)</label>
          <input className="form-input" type="number" value={ruleForm.timeWindowSeconds} onChange={e => setRuleForm(p => ({ ...p, timeWindowSeconds: e.target.value }))} placeholder="Optional" />
        </div>
      </div>
      <div>
        <label style={labelStyle}>Rule Logic</label>
        <textarea className="form-input" rows={3} value={ruleForm.ruleLogic} onChange={e => setRuleForm(p => ({ ...p, ruleLogic: e.target.value }))} placeholder="Rule logic expression" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }} />
      </div>
      <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
        <input type="checkbox" checked={ruleForm.isActive} onChange={e => setRuleForm(p => ({ ...p, isActive: e.target.checked }))} />
        Is Active
      </label>
      <button className="btn btn-primary" onClick={handleSaveRule} disabled={ruleSaving} style={{ marginTop: 4 }}>
        {ruleSaving ? <Loader size={14} className="spin" /> : <Save size={14} />} {ruleModal === 'create' ? 'Create Rule' : 'Save Changes'}
      </button>
    </div>
  );

  // ────────────────────────────────────────────────────────
  // RENDER
  // ────────────────────────────────────────────────────────
  return (
    <motion.div variants={container} initial="hidden" animate="show">
      <motion.div variants={item} className="page-header">
        <div>
          <h2>Settings</h2>
          <p>Detection rules, user management &amp; security</p>
        </div>
      </motion.div>

      {/* ── Tab Switcher ── */}
      <motion.div variants={item} style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-elevated)', padding: 4, borderRadius: 10, width: 'fit-content' }}>
        {[
          { key: 'rules', label: 'Detection Rules', icon: Shield },
          { key: 'users', label: 'User Management', icon: Users },
          { key: 'security', label: 'Security (MFA)', icon: KeyRound },
        ].map(({ key, label, icon: Icon }) => (
          <button key={key}
            onClick={() => setTab(key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '8px 18px', borderRadius: 8, border: 'none', cursor: 'pointer',
              fontSize: '0.82rem', fontWeight: 600, transition: 'all 0.2s',
              background: tab === key ? 'var(--cyan-500)' : 'transparent',
              color: tab === key ? 'white' : 'var(--text-muted)',
            }}>
            <Icon size={14} /> {label}
          </button>
        ))}
      </motion.div>

      {error && <div className="login-error">{error}</div>}

      {loading ? (
        <div className="flex items-center justify-center" style={{ padding: 60 }}>
          <Loader className="spin" size={28} style={{ color: 'var(--cyan-400)' }} />
        </div>
      ) : tab === 'security' ? (
        <motion.div variants={item}>
          <MfaSection />
        </motion.div>

      /* ══════════════════════════════════════════════════════
         TAB 1: DETECTION RULES
         ══════════════════════════════════════════════════════ */
      ) : tab === 'rules' ? (
        <>
          <motion.div variants={item} className="card">
            <div className="card-header flex justify-between items-center">
              <h3 style={{ fontSize: '0.92rem', fontWeight: 700 }}>Detection Rules ({rules.length})</h3>
              <button className="btn btn-primary btn-sm" onClick={openCreateRule}>
                <Plus size={14} /> Create Rule
              </button>
            </div>
            <div className="card-body" style={{ padding: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Rule Name</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>MITRE</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.length === 0 ? (
                    <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>No detection rules found</td></tr>
                  ) : rules.map(rule => (
                    <tr key={rule.id}>
                      <td>
                        <button
                          onClick={() => openRuleDetail(rule)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600, color: 'var(--cyan-400)', textAlign: 'left', padding: 0, fontSize: 'inherit' }}>
                          {rule.name}
                        </button>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', maxWidth: 180 }}>{truncate(rule.description, 45)}</td>
                      <td><span className={`severity-badge ${(rule.severity || 'medium').toLowerCase()}`}>{rule.severity || 'Medium'}</span></td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{rule.ruleType || 'Threshold'}</td>
                      <td style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{rule.mitreTechnique || '—'}</td>
                      <td>
                        <button
                          onClick={(e) => { e.stopPropagation(); toggleRule(rule.id, rule.isActive); }}
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: 5,
                            padding: '3px 10px', borderRadius: 20, border: 'none', cursor: 'pointer',
                            fontSize: '0.7rem', fontWeight: 600,
                            background: rule.isActive ? 'rgba(16,185,129,0.12)' : 'rgba(100,116,139,0.12)',
                            color: rule.isActive ? 'var(--green-400)' : 'var(--text-muted)',
                          }}>
                          <Power size={10} /> {rule.isActive ? 'Active' : 'Inactive'}
                        </button>
                      </td>
                      <td>
                        <div className="flex gap-sm">
                          <button className="btn btn-ghost btn-sm" onClick={() => openRuleEdit(rule)} style={{ padding: '3px 8px' }} title="Edit">
                            <Edit3 size={12} />
                          </button>
                          <button className="btn btn-danger btn-sm" onClick={() => setConfirmDelete(rule)} style={{ padding: '3px 8px' }} title="Delete">
                            <Trash2 size={12} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>

          {/* ── Create Rule Modal ── */}
          <ModalShell open={ruleModal === 'create'} onClose={closeRuleModal}>
            <ModalHeader title="Create Detection Rule" onClose={closeRuleModal} />
            {renderRuleFormFields()}
          </ModalShell>

          {/* ── Edit Rule Modal ── */}
          <ModalShell open={ruleModal === 'edit'} onClose={closeRuleModal}>
            <ModalHeader title={`Edit Rule: ${selectedRule?.name || ''}`} onClose={closeRuleModal} />
            {ruleDetailLoading ? (
              <div style={{ padding: 40, textAlign: 'center' }}><Loader size={24} className="spin" style={{ color: 'var(--cyan-400)' }} /></div>
            ) : renderRuleFormFields()}
          </ModalShell>

          {/* ── Rule Detail Modal ── */}
          <ModalShell open={ruleModal === 'detail'} onClose={closeRuleModal}>
            <ModalHeader
              title={selectedRule?.name || 'Rule Detail'}
              onClose={closeRuleModal}
              actions={
                <button className="btn btn-ghost btn-sm" onClick={() => { if (selectedRule) openRuleEdit(selectedRule); }} title="Edit">
                  <Edit3 size={14} />
                </button>
              }
            />
            {ruleDetailLoading ? (
              <div style={{ padding: 40, textAlign: 'center' }}><Loader size={24} className="spin" style={{ color: 'var(--cyan-400)' }} /></div>
            ) : selectedRule && (
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {selectedRule.description && (
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{selectedRule.description}</div>
                )}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  {[
                    { label: 'Rule Type', value: selectedRule.ruleType || '—' },
                    { label: 'Severity', value: selectedRule.severity || '—' },
                    { label: 'Status', value: selectedRule.isActive ? 'Active' : 'Inactive' },
                    { label: 'Created', value: fmtDate(selectedRule.createdAt) },
                    { label: 'Updated', value: fmtDate(selectedRule.updatedAt) },
                    { label: 'Threshold Count', value: selectedRule.thresholdCount ?? '—' },
                    { label: 'Time Window', value: selectedRule.timeWindowSeconds ? `${selectedRule.timeWindowSeconds}s` : '—' },
                    { label: 'Runtime Enabled', value: selectedRule.runtimeEnabled != null ? String(selectedRule.runtimeEnabled) : '—' },
                  ].map(f => (
                    <div key={f.label} style={infoBoxStyle}>
                      <div style={infoLabelStyle}>{f.label}</div>
                      <div style={infoValueStyle}>{f.value}</div>
                    </div>
                  ))}
                </div>

                {/* MITRE Mapping */}
                {(selectedRule.mitreTechnique || selectedRule.mitreTactic) && (
                  <div style={{ background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)', padding: 14, borderRadius: 10 }}>
                    <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--purple-400)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                      <Shield size={12} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />
                      MITRE ATT&CK Mapping
                    </div>
                    <div style={{ display: 'flex', gap: 16 }}>
                      {selectedRule.mitreTechnique && (
                        <div>
                          <div style={infoLabelStyle}>Technique</div>
                          <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{selectedRule.mitreTechnique}</div>
                        </div>
                      )}
                      {selectedRule.mitreTactic && (
                        <div>
                          <div style={infoLabelStyle}>Tactic</div>
                          <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>{selectedRule.mitreTactic}</div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Rule Logic */}
                {selectedRule.ruleLogic && (
                  <div style={{ background: 'var(--bg-deep)', padding: 12, borderRadius: 8 }}>
                    <div style={infoLabelStyle}>Rule Logic</div>
                    <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--cyan-400)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, background: 'rgba(0,0,0,0.2)', padding: 10, borderRadius: 6, marginTop: 6 }}>
                      <code>{selectedRule.ruleLogic}</code>
                    </pre>
                  </div>
                )}
              </div>
            )}
          </ModalShell>

          {/* ── Delete Confirmation Dialog ── */}
          <ModalShell open={!!confirmDelete} onClose={() => setConfirmDelete(null)}>
            <div className="card-body" style={{ textAlign: 'center', padding: '30px 24px' }}>
              <AlertTriangle size={40} style={{ color: 'var(--red-400)', marginBottom: 12 }} />
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>Delete Detection Rule?</h3>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 20 }}>
                Are you sure you want to delete <strong>{confirmDelete?.name}</strong>? This action cannot be undone.
              </p>
              <div className="flex gap-sm" style={{ justifyContent: 'center' }}>
                <button className="btn btn-ghost" onClick={() => setConfirmDelete(null)}>Cancel</button>
                <button className="btn btn-danger" onClick={() => deleteRule(confirmDelete.id)}>
                  <Trash2 size={14} /> Delete
                </button>
              </div>
            </div>
          </ModalShell>
        </>

      /* ══════════════════════════════════════════════════════
         TAB 2: USER MANAGEMENT
         ══════════════════════════════════════════════════════ */
      ) : (
        <>
          <motion.div variants={item} className="card">
            <div className="card-header flex justify-between items-center">
              <h3 style={{ fontSize: '0.92rem', fontWeight: 700 }}>Users ({users.length})</h3>
              <button className="btn btn-primary btn-sm" onClick={openCreateUser}>
                <UserPlus size={14} /> Create User
              </button>
            </div>
            <div className="card-body" style={{ padding: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.length === 0 ? (
                    <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>No users found</td></tr>
                  ) : users.map(u => {
                    const rc = ROLE_COLORS[u.role] || { bg: 'rgba(100,116,139,0.12)', color: 'var(--text-muted)' };
                    return (
                      <tr key={u.id}>
                        <td>
                          <button
                            onClick={() => openUserDetail(u)}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600, color: 'var(--cyan-400)', textAlign: 'left', padding: 0, fontSize: 'inherit' }}>
                            {u.username}
                          </button>
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{u.email}</td>
                        <td>
                          <span style={{ padding: '2px 10px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600, background: rc.bg, color: rc.color }}>
                            {u.role}
                          </span>
                        </td>
                        <td>
                          <span style={{
                            padding: '2px 8px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600,
                            background: u.isActive ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)',
                            color: u.isActive ? 'var(--green-400)' : 'var(--red-400)',
                          }}>{u.isActive ? 'Active' : 'Inactive'}</span>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {u.lastLogin ? new Date(u.lastLogin).toLocaleDateString() : 'Never'}
                        </td>
                        <td>
                          <div className="flex gap-sm">
                            <button className="btn btn-ghost btn-sm" onClick={() => openUserEdit(u)} style={{ padding: '3px 8px' }} title="Edit">
                              <Edit3 size={12} />
                            </button>
                            {u.isActive ? (
                              <button className="btn btn-danger btn-sm" onClick={() => handleDeactivateUser(u)} style={{ padding: '3px 8px' }} title="Deactivate">
                                <Power size={12} />
                              </button>
                            ) : (
                              <button className="btn btn-ghost btn-sm" onClick={() => handleReactivateUser(u)} style={{ padding: '3px 8px', color: 'var(--green-400)' }} title="Reactivate">
                                <CheckCircle size={12} />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </motion.div>

          {/* ── Create User Modal ── */}
          <ModalShell open={userModal === 'create'} onClose={closeUserModal}>
            <ModalHeader title="Create New User" onClose={closeUserModal} />
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label style={labelStyle}>Username *</label>
                <input className="form-input" value={userForm.username} onChange={e => setUserForm(p => ({ ...p, username: e.target.value }))} placeholder="Enter username" />
              </div>
              <div>
                <label style={labelStyle}>Email *</label>
                <input className="form-input" type="email" value={userForm.email} onChange={e => setUserForm(p => ({ ...p, email: e.target.value }))} placeholder="user@example.com" />
              </div>
              <div>
                <label style={labelStyle}>Password *</label>
                <input className="form-input" type="password" value={userForm.password} onChange={e => setUserForm(p => ({ ...p, password: e.target.value }))} placeholder="Min 8 characters" minLength={8} />
              </div>
              <div>
                <label style={labelStyle}>Role</label>
                <select className="form-select" value={userForm.roleId} onChange={e => setUserForm(p => ({ ...p, roleId: e.target.value }))}>
                  {ROLES.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select>
              </div>
              <button className="btn btn-primary" onClick={handleCreateUser} disabled={userSaving} style={{ marginTop: 4 }}>
                {userSaving ? <Loader size={14} className="spin" /> : <UserPlus size={14} />} Create User
              </button>
            </div>
          </ModalShell>

          {/* ── Edit User Modal ── */}
          <ModalShell open={userModal === 'edit'} onClose={closeUserModal}>
            <ModalHeader title={`Edit User: ${selectedUser?.username || ''}`} onClose={closeUserModal} />
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label style={labelStyle}>Email</label>
                <input className="form-input" type="email" value={userForm.email} onChange={e => setUserForm(p => ({ ...p, email: e.target.value }))} />
              </div>
              <div>
                <label style={labelStyle}>Role</label>
                <select className="form-select" value={userForm.roleId} onChange={e => setUserForm(p => ({ ...p, roleId: e.target.value }))}>
                  {ROLES.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select>
              </div>
              <div>
                <label style={labelStyle}>Status</label>
                <select className="form-select" value={selectedUser?.isActive ? 'active' : 'inactive'}
                  onChange={e => setSelectedUser(p => ({ ...p, isActive: e.target.value === 'active' }))}>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>
              <button className="btn btn-primary" onClick={handleUpdateUser} disabled={userSaving} style={{ marginTop: 4 }}>
                {userSaving ? <Loader size={14} className="spin" /> : <Save size={14} />} Save Changes
              </button>
            </div>
          </ModalShell>

          {/* ── User Detail Modal ── */}
          <ModalShell open={userModal === 'detail'} onClose={closeUserModal}>
            <ModalHeader
              title={selectedUser?.username || 'User Detail'}
              onClose={closeUserModal}
              actions={
                <button className="btn btn-ghost btn-sm" onClick={() => { if (selectedUser) openUserEdit(selectedUser); }} title="Edit">
                  <Edit3 size={14} />
                </button>
              }
            />
            {selectedUser && (
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  {[
                    { label: 'Username', value: selectedUser.username },
                    { label: 'Email', value: selectedUser.email },
                    { label: 'Role', value: selectedUser.role },
                    { label: 'Status', value: selectedUser.isActive ? 'Active' : 'Inactive' },
                    { label: 'Last Login', value: selectedUser.lastLogin ? new Date(selectedUser.lastLogin).toLocaleString() : 'Never' },
                    { label: 'Created At', value: fmtDate(selectedUser.createdAt) },
                  ].map(f => (
                    <div key={f.label} style={infoBoxStyle}>
                      <div style={infoLabelStyle}>{f.label}</div>
                      <div style={infoValueStyle}>{f.value}</div>
                    </div>
                  ))}
                </div>

                {/* Permissions */}
                {selectedUser.permissions && selectedUser.permissions.length > 0 && (
                  <div style={infoBoxStyle}>
                    <div style={{ ...infoLabelStyle, marginBottom: 8 }}>Permissions</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {selectedUser.permissions.map(p => (
                        <span key={p} style={{ padding: '2px 10px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600, background: 'rgba(6,182,212,0.12)', color: 'var(--cyan-400)' }}>
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex gap-sm" style={{ marginTop: 4 }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => openUserEdit(selectedUser)}>
                    <Edit3 size={14} /> Edit User
                  </button>
                  {selectedUser.isActive ? (
                    <button className="btn btn-danger btn-sm" onClick={() => handleDeactivateUser(selectedUser)}>
                      <Power size={14} /> Deactivate
                    </button>
                  ) : (
                    <button className="btn btn-primary btn-sm" onClick={() => handleReactivateUser(selectedUser)}>
                      <CheckCircle size={14} /> Reactivate
                    </button>
                  )}
                </div>
              </div>
            )}
          </ModalShell>
        </>
      )}
    </motion.div>
  );
}
