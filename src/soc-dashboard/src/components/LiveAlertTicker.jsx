import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radio, AlertTriangle, Users } from 'lucide-react';
import { useAlertStream } from '../hooks/useAlertStream';
import { useToast } from './ToastContext.js';

const SEVERITY_COLOR = {
    Critical: 'var(--red-400, #f87171)',
    High: 'var(--amber-400, #fbbf24)',
    Medium: 'var(--cyan-400, #5fb4ff)',
    Low: 'var(--text-muted, #a3b1c6)',
};

export default function LiveAlertTicker({ max = 6 }) {
    const { alerts, status, userCount, latest } = useAlertStream(max);
    const toast = useToast();
    const firedRef = useRef(new Set());

    // Toast on every NEW Critical alert (once per id)
    useEffect(() => {
        if (!latest || latest.severity !== 'Critical') return;
        if (firedRef.current.has(latest.id)) return;
        firedRef.current.add(latest.id);
        toast?.error?.(`Critical alert — ${latest.title}`);
    }, [latest, toast]);

    const dotColor = status === 'connected' ? '#10b981' : status === 'reconnecting' ? '#fbbf24' : '#6b7280';

    return (
        <div style={{
            background: 'var(--bg-elevated, #101a2e)',
            border: '1px solid var(--border, #1f2c44)',
            borderRadius: 10,
            padding: 16,
        }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Radio size={16} style={{ color: dotColor }} />
                    <strong style={{ fontSize: '0.9rem' }}>Live alert stream</strong>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        {status}
                    </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    <Users size={14} /> {userCount} online
                </div>
            </div>

            {alerts.length === 0 && (
                <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>
                    Waiting for detections — the engine pushes every alert the moment it fires.
                </p>
            )}

            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                <AnimatePresence initial={false}>
                    {alerts.map((a) => (
                        <motion.li
                            key={a.id}
                            initial={{ opacity: 0, y: -6, scale: 0.98 }}
                            animate={{ opacity: 1, y: 0, scale: 1 }}
                            exit={{ opacity: 0, y: 6 }}
                            transition={{ duration: 0.25 }}
                            style={{
                                display: 'flex', alignItems: 'center', gap: 10,
                                padding: '8px 10px',
                                borderLeft: `3px solid ${SEVERITY_COLOR[a.severity] ?? SEVERITY_COLOR.Low}`,
                                marginBottom: 6,
                                background: 'var(--bg, #0b1320)',
                                borderRadius: 6,
                                fontSize: '0.8rem',
                            }}
                        >
                            {a.severity === 'Critical' && <AlertTriangle size={14} style={{ color: SEVERITY_COLOR.Critical }} />}
                            <span style={{ color: SEVERITY_COLOR[a.severity] ?? SEVERITY_COLOR.Low, fontWeight: 600, minWidth: 62 }}>
                                {a.severity}
                            </span>
                            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {a.title}
                            </span>
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', whiteSpace: 'nowrap' }}>
                                {new Date(a.createdAt).toLocaleTimeString()}
                            </span>
                        </motion.li>
                    ))}
                </AnimatePresence>
            </ul>
        </div>
    );
}
