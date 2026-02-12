import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Settings as SettingsIcon, Shield, Users, Plus, X, Edit3, Trash2, Power, Loader, Save } from 'lucide-react';
import { api } from '../api';
import { useToast } from '../components/Toast';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.06 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

export default function Settings() {
    const [tab, setTab] = useState('rules');
    const [rules, setRules] = useState([]);
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [editUser, setEditUser] = useState(null);
    const toast = useToast();

    // ── Rules ──
    const fetchRules = async () => {
        setLoading(true);
        const res = await api.getRules();
        if (res.success) setRules(res.data || []);
        else setError('Failed to load rules');
        setLoading(false);
    };

    const toggleRule = async (id, isEnabled) => {
        await api.toggleRule(id, !isEnabled);
        setRules(prev => prev.map(r => r.id === id ? { ...r, isEnabled: !r.isEnabled } : r));
        toast.success(`Rule ${isEnabled ? 'disabled' : 'enabled'}`);
    };

    const deleteRule = async (id) => {
        if (!confirm('Delete this detection rule?')) return;
        await api.deleteRule(id);
        setRules(prev => prev.filter(r => r.id !== id));
        toast.error('Rule deleted');
    };

    // ── Users ──
    const fetchUsers = async () => {
        setLoading(true);
        const res = await api.getUsers();
        if (res.success) setUsers(res.data || []);
        else setError('Failed to load users');
        setLoading(false);
    };

    const handleDeactivate = async (id) => {
        if (!confirm('Deactivate this user?')) return;
        await api.deactivateUser(id);
        setUsers(prev => prev.map(u => u.id === id ? { ...u, isActive: false } : u));
        toast.warning('User deactivated');
    };

    const handleSaveUser = async () => {
        if (!editUser) return;
        const res = await api.updateUser(editUser.id, {
            email: editUser.email,
            roleId: editUser.roleId,
            isActive: editUser.isActive,
        });
        if (res.success) {
            setUsers(prev => prev.map(u => u.id === editUser.id ? res.data : u));
            setEditUser(null);
            toast.success('User updated');
        }
    };

    useEffect(() => {
        if (tab === 'rules') fetchRules();
        else fetchUsers();
    }, [tab]);

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Settings</h2>
                    <p>Detection rules and user management</p>
                </div>
            </motion.div>

            {/* Tab Switcher */}
            <motion.div variants={item} style={{ display: 'flex', gap: 4, marginBottom: 20, background: 'var(--bg-elevated)', padding: 4, borderRadius: 10, width: 'fit-content' }}>
                {[
                    { key: 'rules', label: 'Detection Rules', icon: Shield },
                    { key: 'users', label: 'User Management', icon: Users },
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
            ) : tab === 'rules' ? (
                // ── Detection Rules Tab ──
                <motion.div variants={item} className="card">
                    <div className="card-body" style={{ padding: 0 }}>
                        <table className="data-table">
                            <thead><tr><th>Rule Name</th><th>Severity</th><th>Type</th><th>Status</th><th>Actions</th></tr></thead>
                            <tbody>
                                {rules.length === 0 ? (
                                    <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>No detection rules found</td></tr>
                                ) : rules.map(rule => (
                                    <tr key={rule.id}>
                                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</td>
                                        <td><span className={`severity-badge ${(rule.severity || 'medium').toLowerCase()}`}>{rule.severity || 'Medium'}</span></td>
                                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{rule.ruleType || rule.type || 'Threshold'}</td>
                                        <td>
                                            <button
                                                onClick={() => toggleRule(rule.id, rule.isEnabled)}
                                                style={{
                                                    display: 'inline-flex', alignItems: 'center', gap: 5,
                                                    padding: '3px 10px', borderRadius: 20, border: 'none', cursor: 'pointer',
                                                    fontSize: '0.7rem', fontWeight: 600,
                                                    background: rule.isEnabled ? 'rgba(16,185,129,0.12)' : 'rgba(100,116,139,0.12)',
                                                    color: rule.isEnabled ? 'var(--green-400)' : 'var(--text-muted)',
                                                }}>
                                                <Power size={10} /> {rule.isEnabled ? 'Enabled' : 'Disabled'}
                                            </button>
                                        </td>
                                        <td>
                                            <button className="btn btn-danger btn-sm" onClick={() => deleteRule(rule.id)} style={{ padding: '3px 8px' }}>
                                                <Trash2 size={12} />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </motion.div>
            ) : (
                // ── User Management Tab ──
                <>
                    <motion.div variants={item} className="card">
                        <div className="card-body" style={{ padding: 0 }}>
                            <table className="data-table">
                                <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
                                <tbody>
                                    {users.length === 0 ? (
                                        <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 30 }}>No users found</td></tr>
                                    ) : users.map(u => (
                                        <tr key={u.id}>
                                            <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.username}</td>
                                            <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{u.email}</td>
                                            <td><span style={{
                                                padding: '2px 10px', borderRadius: 20, fontSize: '0.7rem', fontWeight: 600,
                                                background: u.role === 'Admin' ? 'rgba(139,92,246,0.15)' : 'rgba(6,182,212,0.12)',
                                                color: u.role === 'Admin' ? 'var(--purple-400)' : 'var(--cyan-400)',
                                            }}>{u.role}</span></td>
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
                                                    <button className="btn btn-ghost btn-sm" onClick={() => setEditUser({ ...u })} style={{ padding: '3px 8px' }}>
                                                        <Edit3 size={12} />
                                                    </button>
                                                    {u.isActive && (
                                                        <button className="btn btn-danger btn-sm" onClick={() => handleDeactivate(u.id)} style={{ padding: '3px 8px' }}>
                                                            <Power size={12} />
                                                        </button>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </motion.div>

                    {/* Edit User Modal */}
                    <AnimatePresence>
                        {editUser && (
                            <motion.div
                                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                                style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                                onClick={() => setEditUser(null)}
                            >
                                <motion.div
                                    initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
                                    className="card" style={{ width: 400, maxHeight: '70vh', overflow: 'auto' }}
                                    onClick={e => e.stopPropagation()}
                                >
                                    <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <h3>Edit User: {editUser.username}</h3>
                                        <button className="btn btn-ghost btn-sm" onClick={() => setEditUser(null)}><X size={16} /></button>
                                    </div>
                                    <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                        <div>
                                            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Email</label>
                                            <input className="form-input" value={editUser.email}
                                                onChange={e => setEditUser({ ...editUser, email: e.target.value })} />
                                        </div>
                                        <div>
                                            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Status</label>
                                            <select className="form-select" value={editUser.isActive ? 'active' : 'inactive'}
                                                onChange={e => setEditUser({ ...editUser, isActive: e.target.value === 'active' })}>
                                                <option value="active">Active</option>
                                                <option value="inactive">Inactive</option>
                                            </select>
                                        </div>
                                        <button className="btn btn-primary" onClick={handleSaveUser} style={{ marginTop: 8 }}>
                                            <Save size={14} /> Save Changes
                                        </button>
                                    </div>
                                </motion.div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </>
            )}
        </motion.div>
    );
}
