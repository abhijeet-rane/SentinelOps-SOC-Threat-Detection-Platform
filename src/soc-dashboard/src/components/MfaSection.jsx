import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { KeyRound, CheckCircle, AlertTriangle, Copy, Check } from 'lucide-react';
import { api } from '../api';
import { useToast } from './ToastContext';

/**
 * Self-service MFA (TOTP) enrollment + disable flow.
 *
 * UX state machine:
 *   idle   →  user clicks "Enable MFA"
 *   setup  →  server returned QR + secret; user scans + enters first code
 *   enabled→  server returned 10 backup codes (shown ONCE)
 *   manage →  MFA is already on; user can see count + Disable
 */
export default function MfaSection() {
    const [state, setState] = useState('loading');      // loading | idle | setup | enabled | manage
    const [setupData, setSetupData] = useState(null);   // { otpAuthUri, qrCodePngBase64, secretBase32 }
    const [code, setCode] = useState('');
    const [backupCodes, setBackupCodes] = useState([]);
    const [status, setStatus] = useState(null);         // { enabled, enabledAt, remainingBackupCodes }
    const [disablePwd, setDisablePwd] = useState('');
    const [disableCode, setDisableCode] = useState('');
    const [copied, setCopied] = useState(false);
    const [loading, setLoading] = useState(false);
    const toast = useToast();

    useEffect(() => {
        (async () => {
            const res = await api.mfaStatus();
            if (res.success) {
                setStatus(res.data);
                setState(res.data?.enabled ? 'manage' : 'idle');
            } else {
                setState('idle');
            }
        })();
    }, []);

    const beginSetup = async () => {
        setLoading(true);
        const res = await api.mfaSetup();
        if (res.success) {
            setSetupData(res.data);
            setState('setup');
        } else {
            toast.error(res.message || 'Failed to generate secret');
        }
        setLoading(false);
    };

    const confirmEnable = async () => {
        setLoading(true);
        const res = await api.mfaEnable(code);
        if (res.success) {
            setBackupCodes(res.data?.backupCodes || []);
            setState('enabled');
            toast.success('MFA enabled');
        } else {
            toast.error(res.errors?.[0] || res.message || 'Invalid code');
        }
        setLoading(false);
    };

    const finishEnrollment = async () => {
        // Refresh status and move into manage view.
        const res = await api.mfaStatus();
        if (res.success) setStatus(res.data);
        setSetupData(null);
        setCode('');
        setBackupCodes([]);
        setState('manage');
    };

    const handleDisable = async () => {
        if (!confirm('Disable multi-factor authentication for your account?')) return;
        setLoading(true);
        const res = await api.mfaDisable(disablePwd, disableCode);
        if (res.success) {
            toast.success('MFA disabled');
            setDisablePwd('');
            setDisableCode('');
            setStatus({ enabled: false, enabledAt: null, remainingBackupCodes: 0 });
            setState('idle');
        } else {
            toast.error(res.errors?.[0] || res.message || 'Could not disable MFA');
        }
        setLoading(false);
    };

    const copyBackupCodes = async () => {
        await navigator.clipboard.writeText(backupCodes.join('\n'));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    if (state === 'loading') {
        return <div className="card"><div className="card-body">Loading MFA status…</div></div>;
    }

    // ─── idle: no MFA yet ───
    if (state === 'idle') {
        return (
            <motion.div className="card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="card-body" style={{ padding: 24 }}>
                    <div className="flex items-center gap-sm" style={{ marginBottom: 12 }}>
                        <KeyRound size={18} style={{ color: 'var(--cyan-400)' }} />
                        <h3 style={{ margin: 0 }}>Two-factor authentication (TOTP)</h3>
                    </div>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', lineHeight: 1.6 }}>
                        Add a second layer of protection to your account. After you enter your password you&rsquo;ll also
                        be asked for a 6-digit code from an authenticator app (Google Authenticator, Authy, 1Password).
                        SOC Manager and System Administrator accounts are <strong>required</strong> to enable MFA.
                    </p>
                    <motion.button
                        className="btn btn-primary"
                        onClick={beginSetup}
                        disabled={loading}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        style={{ marginTop: 16 }}>
                        {loading ? 'Generating…' : 'Enable MFA'}
                    </motion.button>
                </div>
            </motion.div>
        );
    }

    // ─── setup: QR + confirm code ───
    if (state === 'setup' && setupData) {
        return (
            <motion.div className="card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="card-body" style={{ padding: 24 }}>
                    <h3 style={{ marginTop: 0 }}>Scan with your authenticator app</h3>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        Open Google Authenticator / Authy / 1Password and scan the QR code. Or paste the secret manually.
                    </p>

                    <div className="flex items-center gap-sm" style={{ marginTop: 16, flexWrap: 'wrap' }}>
                        <img
                            alt="TOTP QR code"
                            src={`data:image/png;base64,${setupData.qrCodePngBase64}`}
                            style={{ width: 200, height: 200, background: '#fff', padding: 8, borderRadius: 8 }} />
                        <div style={{ flex: 1, minWidth: 240 }}>
                            <label className="form-label">Secret (manual entry)</label>
                            <code style={{
                                display: 'block', padding: 10, background: 'var(--bg-elevated)',
                                borderRadius: 6, wordBreak: 'break-all', fontSize: '0.75rem', color: 'var(--cyan-400)'
                            }}>
                                {setupData.secretBase32}
                            </code>
                        </div>
                    </div>

                    <div className="form-group" style={{ marginTop: 20 }}>
                        <label className="form-label">Enter the 6-digit code from your app to confirm</label>
                        <input
                            type="text"
                            inputMode="numeric"
                            maxLength={6}
                            className="form-input"
                            value={code}
                            onChange={e => setCode(e.target.value.trim())}
                            placeholder="000000"
                            autoFocus />
                    </div>

                    <motion.button
                        className="btn btn-primary"
                        onClick={confirmEnable}
                        disabled={loading || code.length !== 6}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}>
                        {loading ? 'Verifying…' : 'Confirm and enable'}
                    </motion.button>
                </div>
            </motion.div>
        );
    }

    // ─── enabled: show backup codes ONCE ───
    if (state === 'enabled') {
        return (
            <motion.div className="card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="card-body" style={{ padding: 24 }}>
                    <div className="flex items-center gap-sm" style={{ marginBottom: 10 }}>
                        <CheckCircle size={20} style={{ color: 'var(--green-400)' }} />
                        <h3 style={{ margin: 0 }}>MFA is now active</h3>
                    </div>

                    <div style={{
                        padding: 12, background: 'rgba(251,191,36,0.1)',
                        border: '1px solid rgba(251,191,36,0.3)', borderRadius: 8,
                        fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: 12
                    }}>
                        <AlertTriangle size={16} style={{ verticalAlign: 'middle', color: 'var(--amber-400)', marginRight: 6 }} />
                        Save these 10 single-use backup codes somewhere safe. <strong>They will not be shown again.</strong>
                    </div>

                    <div style={{
                        marginTop: 14, padding: 14, background: 'var(--bg-elevated)',
                        borderRadius: 8, fontFamily: 'var(--font-mono)', fontSize: '0.9rem',
                        display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8,
                    }}>
                        {backupCodes.map((c) => <div key={c} style={{ color: 'var(--cyan-400)' }}>{c}</div>)}
                    </div>

                    <div className="flex gap-sm" style={{ marginTop: 16 }}>
                        <button className="btn btn-ghost" onClick={copyBackupCodes}>
                            {copied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy all</>}
                        </button>
                        <button className="btn btn-primary" onClick={finishEnrollment}>
                            I&rsquo;ve saved them — continue
                        </button>
                    </div>
                </div>
            </motion.div>
        );
    }

    // ─── manage: already enabled ───
    return (
        <motion.div className="card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <div className="card-body" style={{ padding: 24 }}>
                <div className="flex items-center gap-sm" style={{ marginBottom: 12 }}>
                    <CheckCircle size={18} style={{ color: 'var(--green-400)' }} />
                    <h3 style={{ margin: 0 }}>MFA is enabled</h3>
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                    Enabled on {status?.enabledAt ? new Date(status.enabledAt).toLocaleString() : '—'}.<br />
                    {status?.remainingBackupCodes ?? 0} of 10 backup codes remaining.
                </div>

                <h4 style={{ marginTop: 24, marginBottom: 10 }}>Disable MFA</h4>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    We need your current password AND a code from your authenticator so a stolen session cannot turn
                    off your second factor.
                </p>

                <div className="form-group">
                    <label className="form-label">Current password</label>
                    <input type="password" className="form-input" value={disablePwd}
                        onChange={e => setDisablePwd(e.target.value)} />
                </div>
                <div className="form-group">
                    <label className="form-label">Current 6-digit code</label>
                    <input type="text" inputMode="numeric" maxLength={6} className="form-input"
                        value={disableCode} onChange={e => setDisableCode(e.target.value.trim())}
                        placeholder="000000" />
                </div>

                <button className="btn btn-danger" onClick={handleDisable}
                    disabled={loading || !disablePwd || disableCode.length !== 6}>
                    {loading ? 'Disabling…' : 'Disable MFA'}
                </button>
            </div>
        </motion.div>
    );
}
