import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, User, Lock, ArrowRight, KeyRound } from 'lucide-react';
import { api, setToken } from '../api';
import MfaEnrollmentWizard from '../components/MfaEnrollmentWizard';

// Two-step login: password → (if required) MFA challenge → access token.
export default function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    // Step-2 state once MFA is required
    const [mfaToken, setMfaToken] = useState(null);
    const [mfaEnrollmentRequired, setMfaEnrollmentRequired] = useState(false);
    const [useBackupCode, setUseBackupCode] = useState(false);
    const [code, setCode] = useState('');

    const completeLogin = (data) => {
        setToken(data.accessToken);
        localStorage.setItem('soc_user', JSON.stringify({
            username: data.user?.username || username,
            role: data.user?.role || 'Analyst',
        }));
        navigate('/');
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const res = await api.login(username, password);
            if (!res.success) {
                setError(res.errors?.[0] || res.message || 'Invalid credentials');
                setLoading(false);
                return;
            }

            if (res.data?.mfaRequired) {
                setMfaToken(res.data.mfaToken);
                setMfaEnrollmentRequired(!!res.data.mfaEnrollmentRequired);
                setLoading(false);
                return;
            }

            if (res.data?.accessToken) {
                completeLogin(res.data);
            } else {
                setError('Unexpected response from server');
            }
        } catch {
            setError('Connection failed. Is the API server running?');
        }
        setLoading(false);
    };

    const handleMfaSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const res = useBackupCode
                ? await api.mfaBackup(mfaToken, code)
                : await api.mfaVerify(mfaToken, code);

            if (res.success && res.data?.accessToken) {
                completeLogin(res.data);
            } else {
                setError(res.errors?.[0] || res.message || (useBackupCode ? 'Invalid backup code' : 'Invalid code'));
            }
        } catch {
            setError('Connection failed during MFA verification.');
        }
        setLoading(false);
    };

    const resetToStepOne = () => {
        setMfaToken(null);
        setMfaEnrollmentRequired(false);
        setUseBackupCode(false);
        setCode('');
        setError('');
    };

    return (
        <div className="login-page">
            <div className="login-bg-effect" />
            <div className="cyber-grid-bg" />

            {[...Array(6)].map((_, i) => (
                <motion.div key={i}
                    style={{
                        position: 'absolute', width: 4, height: 4,
                        background: 'var(--cyan-400)', borderRadius: '50%',
                        opacity: 0.3, left: `${15 + i * 14}%`, top: `${20 + (i % 3) * 25}%`,
                    }}
                    animate={{ y: [0, -30, 0], opacity: [0.2, 0.5, 0.2] }}
                    transition={{ duration: 3 + i * 0.5, repeat: Infinity, ease: 'easeInOut' }}
                />
            ))}

            <motion.div
                className="login-card"
                initial={{ opacity: 0, y: 30, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
            >
                <div className="logo-section">
                    <motion.div className="login-logo" initial={{ rotate: -10 }} animate={{ rotate: 0 }} transition={{ duration: 0.8 }}>
                        {mfaToken ? <KeyRound size={30} color="#fff" /> : <Shield size={30} color="#fff" />}
                    </motion.div>
                    <h2>SENTINEL SOC</h2>
                    <p className="login-subtitle">
                        {mfaToken
                            ? (mfaEnrollmentRequired ? 'MFA enrollment required' : 'Two-factor verification')
                            : 'Security Operations Center Platform'}
                    </p>
                </div>

                {error && (
                    <motion.div className="login-error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                        {error}
                    </motion.div>
                )}

                {/* ─── Step 1: password ─── */}
                {!mfaToken && (
                    <form onSubmit={handleLogin}>
                        <div className="form-group">
                            <label className="form-label">Username</label>
                            <div style={{ position: 'relative' }}>
                                <input type="text" className="form-input" placeholder="Enter your username"
                                    value={username} onChange={(e) => setUsername(e.target.value)}
                                    style={{ paddingLeft: 38 }} required />
                                <User size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <div style={{ position: 'relative' }}>
                                <input type="password" className="form-input" placeholder="Enter your password"
                                    value={password} onChange={(e) => setPassword(e.target.value)}
                                    style={{ paddingLeft: 38 }} required />
                                <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                            </div>
                        </div>

                        <motion.button type="submit" className="btn btn-primary" disabled={loading}
                            whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} style={{ marginTop: 8 }}>
                            {loading ? 'Authenticating...' : (<>Sign In <ArrowRight size={16} /></>)}
                        </motion.button>

                        <p style={{ textAlign: 'center', marginTop: 18, fontSize: '0.8rem' }}>
                            <Link to="/forgot-password" style={{ color: 'var(--cyan-400)', textDecoration: 'none' }}>
                                Forgot password?
                            </Link>
                        </p>
                    </form>
                )}

                {/* ─── Step 2: MFA challenge ─── */}
                {mfaToken && !mfaEnrollmentRequired && (
                    <form onSubmit={handleMfaSubmit}>
                        <div className="form-group">
                            <label className="form-label">
                                {useBackupCode ? 'Backup code' : '6-digit code from your authenticator app'}
                            </label>
                            <input
                                type="text"
                                className="form-input"
                                placeholder={useBackupCode ? 'XXXX-XXXX' : '000000'}
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                autoFocus
                                inputMode={useBackupCode ? 'text' : 'numeric'}
                                maxLength={useBackupCode ? 12 : 6}
                                required
                            />
                        </div>

                        <motion.button type="submit" className="btn btn-primary" disabled={loading}
                            whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} style={{ marginTop: 8 }}>
                            {loading ? 'Verifying...' : (<>Verify <ArrowRight size={16} /></>)}
                        </motion.button>

                        <p style={{ textAlign: 'center', marginTop: 14, fontSize: '0.8rem' }}>
                            <button type="button"
                                onClick={() => { setUseBackupCode(!useBackupCode); setCode(''); setError(''); }}
                                style={{ background: 'none', border: 'none', color: 'var(--cyan-400)', cursor: 'pointer', textDecoration: 'underline' }}>
                                {useBackupCode ? 'Use authenticator code instead' : 'Use a backup code instead'}
                            </button>
                        </p>
                        <p style={{ textAlign: 'center', marginTop: 6, fontSize: '0.75rem' }}>
                            <button type="button" onClick={resetToStepOne}
                                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                                ← Back to sign in
                            </button>
                        </p>
                    </form>
                )}

                {/* ─── Step 2 alt: first-time enrollment (priv roles w/o MFA) ─── */}
                {mfaToken && mfaEnrollmentRequired && (
                    <MfaEnrollmentWizard
                        mfaToken={mfaToken}
                        onCancel={resetToStepOne}
                        onSuccess={(data) => completeLogin(data)} />
                )}

                <p style={{ textAlign: 'center', marginTop: 12, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Protected system · Unauthorized access prohibited
                </p>
            </motion.div>
        </div>
    );
}
