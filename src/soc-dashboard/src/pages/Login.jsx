import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, User, Lock, ArrowRight } from 'lucide-react';
import { api, setToken } from '../api';

export default function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const res = await api.login(username, password);
            if (res.success && (res.data?.accessToken || res.data?.token)) {
                setToken(res.data.accessToken || res.data.token);
                localStorage.setItem('soc_user', JSON.stringify({
                    username: res.data.user?.username || res.data.username || username,
                    role: res.data.user?.role || res.data.role || 'Analyst',
                }));
                navigate('/');
            } else {
                setError(res.errors?.[0] || res.message || 'Invalid credentials');
            }
        } catch {
            setError('Connection failed. Is the API server running?');
        }
        setLoading(false);
    };

    return (
        <div className="login-page">
            <div className="login-bg-effect" />
            <div className="cyber-grid-bg" />

            {/* Floating particles */}
            {[...Array(6)].map((_, i) => (
                <motion.div key={i}
                    style={{
                        position: 'absolute',
                        width: 4, height: 4,
                        background: 'var(--cyan-400)',
                        borderRadius: '50%',
                        opacity: 0.3,
                        left: `${15 + i * 14}%`,
                        top: `${20 + (i % 3) * 25}%`,
                    }}
                    animate={{
                        y: [0, -30, 0],
                        opacity: [0.2, 0.5, 0.2],
                    }}
                    transition={{
                        duration: 3 + i * 0.5,
                        repeat: Infinity,
                        ease: 'easeInOut',
                    }}
                />
            ))}

            <motion.div
                className="login-card"
                initial={{ opacity: 0, y: 30, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
            >
                <div className="logo-section">
                    <motion.div
                        className="login-logo"
                        initial={{ rotate: -10 }}
                        animate={{ rotate: 0 }}
                        transition={{ duration: 0.8 }}
                    >
                        <Shield size={30} color="#fff" />
                    </motion.div>
                    <h2>SENTINEL SOC</h2>
                    <p className="login-subtitle">Security Operations Center Platform</p>
                </div>

                {error && (
                    <motion.div className="login-error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                        {error}
                    </motion.div>
                )}

                <form onSubmit={handleLogin}>
                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                type="text"
                                className="form-input"
                                placeholder="Enter your username"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                style={{ paddingLeft: 38 }}
                                required
                            />
                            <User size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                        </div>
                    </div>

                    <div className="form-group">
                        <label className="form-label">Password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                type="password"
                                className="form-input"
                                placeholder="Enter your password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                style={{ paddingLeft: 38 }}
                                required
                            />
                            <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                        </div>
                    </div>

                    <motion.button
                        type="submit"
                        className="btn btn-primary"
                        disabled={loading}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        style={{ marginTop: 8 }}
                    >
                        {loading ? 'Authenticating...' : (<>Sign In <ArrowRight size={16} /></>)}
                    </motion.button>
                </form>

                <p style={{ textAlign: 'center', marginTop: 24, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Protected system · Unauthorized access prohibited
                </p>
            </motion.div>
        </div>
    );
}
