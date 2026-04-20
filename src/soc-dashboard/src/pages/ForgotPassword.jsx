import { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Mail, ArrowRight, ArrowLeft, CheckCircle2 } from 'lucide-react';
import { api } from '../api';

export default function ForgotPassword() {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const res = await api.forgotPassword(email);
            // Server is enumeration-safe — always 202 — so we always show the success state
            if (res && (res.success === true || res.success === undefined)) {
                setSubmitted(true);
            } else {
                setError(res.message || 'Unable to process request. Please try again.');
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

            <motion.div
                className="login-card"
                initial={{ opacity: 0, y: 30, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
            >
                <div className="logo-section">
                    <motion.div className="login-logo" initial={{ rotate: -10 }} animate={{ rotate: 0 }} transition={{ duration: 0.8 }}>
                        <Shield size={30} color="#fff" />
                    </motion.div>
                    <h2>RESET PASSWORD</h2>
                    <p className="login-subtitle">We'll email you a secure reset link</p>
                </div>

                {error && (
                    <motion.div className="login-error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                        {error}
                    </motion.div>
                )}

                {submitted ? (
                    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                        style={{ textAlign: 'center', padding: '20px 0' }}>
                        <CheckCircle2 size={42} color="var(--cyan-400)" style={{ marginBottom: 12 }} />
                        <h3 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)' }}>Check your inbox</h3>
                        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', lineHeight: 1.5 }}>
                            If an account exists for <strong style={{ color: 'var(--text-primary)' }}>{email}</strong>,
                            a reset link has been sent. The link expires in 60 minutes.
                        </p>
                    </motion.div>
                ) : (
                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label className="form-label">Email address</label>
                            <div style={{ position: 'relative' }}>
                                <input
                                    type="email"
                                    className="form-input"
                                    placeholder="you@company.com"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    style={{ paddingLeft: 38 }}
                                    required
                                />
                                <Mail size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
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
                            {loading ? 'Sending...' : (<>Send reset link <ArrowRight size={16} /></>)}
                        </motion.button>
                    </form>
                )}

                <p style={{ textAlign: 'center', marginTop: 18, fontSize: '0.8rem' }}>
                    <Link to="/login" style={{ color: 'var(--cyan-400)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <ArrowLeft size={14} /> Back to sign in
                    </Link>
                </p>
            </motion.div>
        </div>
    );
}
