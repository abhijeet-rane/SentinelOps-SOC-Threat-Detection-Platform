import { useState, useMemo } from 'react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Lock, ArrowRight, CheckCircle2, AlertTriangle } from 'lucide-react';
import { api } from '../api';

const PW_RULES = [
    { test: (p) => p.length >= 10, label: 'At least 10 characters' },
    { test: (p) => /[A-Z]/.test(p), label: 'One uppercase letter' },
    { test: (p) => /[a-z]/.test(p), label: 'One lowercase letter' },
    { test: (p) => /[0-9]/.test(p), label: 'One digit' },
    { test: (p) => /[^a-zA-Z0-9]/.test(p), label: 'One special character' },
];

export default function ResetPassword() {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const token = searchParams.get('token') || '';

    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    const ruleStatus = useMemo(() => PW_RULES.map((r) => ({ ...r, ok: r.test(password) })), [password]);
    const allValid = ruleStatus.every((r) => r.ok) && password === confirm;
    const passwordsMatch = !confirm || password === confirm;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!allValid) {
            setError('Please satisfy all password requirements and ensure both fields match.');
            return;
        }
        setLoading(true);
        try {
            const res = await api.resetPassword(token, password);
            if (res.success) {
                setSuccess(true);
                setTimeout(() => navigate('/login', { replace: true }), 2500);
            } else {
                setError(res.message || res.errors?.[0] || 'Reset link is invalid or has expired.');
            }
        } catch {
            setError('Connection failed. Is the API server running?');
        }
        setLoading(false);
    };

    if (!token) {
        return (
            <div className="login-page">
                <div className="login-bg-effect" />
                <div className="cyber-grid-bg" />
                <motion.div className="login-card" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}>
                    <div className="logo-section">
                        <AlertTriangle size={42} color="var(--red-400, #f87171)" style={{ margin: '0 auto 12px' }} />
                        <h2>INVALID LINK</h2>
                        <p className="login-subtitle">No reset token was provided.</p>
                    </div>
                    <p style={{ textAlign: 'center', marginTop: 12, fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        Open the most recent reset email and click the link again, or
                        <Link to="/forgot-password" style={{ color: 'var(--cyan-400)', marginLeft: 4 }}>request a new one</Link>.
                    </p>
                </motion.div>
            </div>
        );
    }

    return (
        <div className="login-page">
            <div className="login-bg-effect" />
            <div className="cyber-grid-bg" />

            <motion.div className="login-card" initial={{ opacity: 0, y: 30, scale: 0.96 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.6 }}>
                <div className="logo-section">
                    <motion.div className="login-logo" initial={{ rotate: -10 }} animate={{ rotate: 0 }} transition={{ duration: 0.8 }}>
                        <Shield size={30} color="#fff" />
                    </motion.div>
                    <h2>NEW PASSWORD</h2>
                    <p className="login-subtitle">Choose a strong password for your account</p>
                </div>

                {error && (
                    <motion.div className="login-error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                        {error}
                    </motion.div>
                )}

                {success ? (
                    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ textAlign: 'center', padding: '20px 0' }}>
                        <CheckCircle2 size={42} color="var(--cyan-400)" style={{ marginBottom: 12 }} />
                        <h3 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)' }}>Password updated</h3>
                        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                            Redirecting you to sign in...
                        </p>
                    </motion.div>
                ) : (
                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label className="form-label">New password</label>
                            <div style={{ position: 'relative' }}>
                                <input
                                    type="password"
                                    className="form-input"
                                    placeholder="Choose a new password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    style={{ paddingLeft: 38 }}
                                    required
                                />
                                <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Confirm new password</label>
                            <div style={{ position: 'relative' }}>
                                <input
                                    type="password"
                                    className="form-input"
                                    placeholder="Re-enter the new password"
                                    value={confirm}
                                    onChange={(e) => setConfirm(e.target.value)}
                                    style={{ paddingLeft: 38, borderColor: passwordsMatch ? '' : 'var(--red-400, #f87171)' }}
                                    required
                                />
                                <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                            </div>
                            {!passwordsMatch && (
                                <p style={{ marginTop: 4, fontSize: '0.75rem', color: 'var(--red-400, #f87171)' }}>Passwords don't match</p>
                            )}
                        </div>

                        {/* Password rule checklist */}
                        <ul style={{ listStyle: 'none', padding: 0, margin: '8px 0 16px 0', fontSize: '0.78rem' }}>
                            {ruleStatus.map((r) => (
                                <li key={r.label} style={{ display: 'flex', alignItems: 'center', gap: 6, color: r.ok ? 'var(--cyan-400)' : 'var(--text-muted)', marginBottom: 2 }}>
                                    <CheckCircle2 size={12} style={{ opacity: r.ok ? 1 : 0.4 }} />
                                    {r.label}
                                </li>
                            ))}
                        </ul>

                        <motion.button
                            type="submit"
                            className="btn btn-primary"
                            disabled={loading || !allValid}
                            whileHover={allValid ? { scale: 1.02 } : {}}
                            whileTap={allValid ? { scale: 0.98 } : {}}
                            style={{ marginTop: 4, opacity: allValid ? 1 : 0.6 }}
                        >
                            {loading ? 'Updating...' : (<>Update password <ArrowRight size={16} /></>)}
                        </motion.button>
                    </form>
                )}

                <p style={{ textAlign: 'center', marginTop: 18, fontSize: '0.8rem' }}>
                    <Link to="/login" style={{ color: 'var(--cyan-400)', textDecoration: 'none' }}>
                        Back to sign in
                    </Link>
                </p>
            </motion.div>
        </div>
    );
}
