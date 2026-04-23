import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, CheckCircle, AlertTriangle, Copy, Check } from 'lucide-react';
import { api } from '../api';

/**
 * Login-time MFA enrollment wizard.
 *
 * When /auth/login returns {mfaRequired:true, mfaEnrollmentRequired:true, mfaToken},
 * the caller mounts this component with the mfaToken. On completion, onSuccess
 * is invoked with {accessToken, refreshToken, user, backupCodes}.
 *
 * State machine:
 *   scan   → QR shown, waiting for 6-digit code
 *   codes  → backup codes displayed ONCE, user must acknowledge
 */
export default function MfaEnrollmentWizard({ mfaToken, onSuccess, onCancel }) {
    const [state, setState] = useState('loading');   // loading | scan | codes
    const [setupData, setSetupData] = useState(null); // { qrCodePngBase64, secretBase32, otpAuthUri }
    const [loginPayload, setLoginPayload] = useState(null); // full login returned by enroll-complete
    const [code, setCode] = useState('');
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const [copied, setCopied] = useState(false);

    // ── Kick off: request a pending TOTP secret + QR using the mfaToken ──
    useEffect(() => {
        (async () => {
            const res = await api.mfaEnrollSetup(mfaToken);
            if (res.success) {
                setSetupData(res.data);
                setState('scan');
            } else {
                setError(res.errors?.[0] || res.message || 'Could not generate secret');
            }
        })();
    }, [mfaToken]);

    const submitCode = async (e) => {
        e?.preventDefault();
        setBusy(true);
        setError('');
        const res = await api.mfaEnrollComplete(mfaToken, code);
        if (res.success && res.data?.accessToken) {
            setLoginPayload(res.data);
            setState('codes');
        } else {
            setError(res.errors?.[0] || res.message || 'Invalid code');
        }
        setBusy(false);
    };

    const copyBackupCodes = async () => {
        if (!loginPayload?.backupCodes) return;
        await navigator.clipboard.writeText(loginPayload.backupCodes.join('\n'));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const finish = () => {
        if (!loginPayload) return;
        onSuccess({
            accessToken: loginPayload.accessToken,
            refreshToken: loginPayload.refreshToken,
            user: loginPayload.user,
        });
    };

    if (state === 'loading') {
        return <div style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>Preparing secure enrollment…</div>;
    }

    // ─── Scan the QR + enter first code ───
    if (state === 'scan' && setupData) {
        return (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div style={{
                    padding: 10, background: 'rgba(56,189,248,0.1)',
                    border: '1px solid rgba(56,189,248,0.3)', borderRadius: 8,
                    fontSize: '0.8rem', marginBottom: 14, lineHeight: 1.5,
                }}>
                    Your role requires multi-factor authentication. Scan the QR code with Google Authenticator / Authy / 1Password and enter the 6-digit code to finish enrolling and sign in.
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', marginBottom: 14 }}>
                    <img
                        alt="TOTP QR code"
                        src={`data:image/png;base64,${setupData.qrCodePngBase64}`}
                        style={{ width: 180, height: 180, background: '#fff', padding: 8, borderRadius: 8 }} />
                    <div style={{ flex: 1, minWidth: 200 }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>
                            Or paste this secret into your app manually:
                        </div>
                        <code style={{
                            display: 'block', padding: 8, background: 'var(--bg-elevated)',
                            borderRadius: 6, wordBreak: 'break-all', fontSize: '0.72rem', color: 'var(--cyan-400)',
                        }}>
                            {setupData.secretBase32}
                        </code>
                    </div>
                </div>

                {error && (
                    <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>
                )}

                <form onSubmit={submitCode}>
                    <div className="form-group">
                        <label className="form-label">6-digit code from your app</label>
                        <input
                            type="text"
                            inputMode="numeric"
                            maxLength={6}
                            className="form-input"
                            placeholder="000000"
                            value={code}
                            onChange={(e) => setCode(e.target.value.trim())}
                            autoFocus
                            required />
                    </div>

                    <motion.button
                        type="submit"
                        className="btn btn-primary"
                        disabled={busy || code.length !== 6}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        style={{ width: '100%' }}>
                        {busy ? 'Enrolling…' : (<>Enroll and sign in <ArrowRight size={16} /></>)}
                    </motion.button>

                    <p style={{ textAlign: 'center', marginTop: 10, fontSize: '0.75rem' }}>
                        <button type="button" onClick={onCancel}
                            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                            Cancel
                        </button>
                    </p>
                </form>
            </motion.div>
        );
    }

    // ─── Show backup codes once ───
    if (state === 'codes' && loginPayload) {
        return (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div style={{ textAlign: 'center', marginBottom: 10 }}>
                    <CheckCircle size={22} style={{ color: 'var(--green-400)' }} />
                    <h3 style={{ margin: '6px 0 0' }}>MFA enabled</h3>
                </div>

                <div style={{
                    padding: 10, background: 'rgba(251,191,36,0.1)',
                    border: '1px solid rgba(251,191,36,0.3)', borderRadius: 8,
                    fontSize: '0.8rem', marginTop: 8, lineHeight: 1.5,
                }}>
                    <AlertTriangle size={14} style={{ verticalAlign: 'middle', color: 'var(--amber-400)', marginRight: 6 }} />
                    Save these 10 single-use backup codes somewhere safe. <strong>They will not be shown again.</strong>
                </div>

                <div style={{
                    marginTop: 12, padding: 12, background: 'var(--bg-elevated)',
                    borderRadius: 8, fontFamily: 'var(--font-mono)', fontSize: '0.85rem',
                    display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6,
                }}>
                    {loginPayload.backupCodes.map((c) => (
                        <div key={c} style={{ color: 'var(--cyan-400)' }}>{c}</div>
                    ))}
                </div>

                <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                    <button className="btn btn-ghost" onClick={copyBackupCodes} style={{ flex: 1 }}>
                        {copied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy all</>}
                    </button>
                    <button className="btn btn-primary" onClick={finish} style={{ flex: 1 }}>
                        I&rsquo;ve saved them — sign in
                    </button>
                </div>
            </motion.div>
        );
    }

    return (
        <div className="login-error">{error || 'Unexpected enrollment state.'}</div>
    );
}
