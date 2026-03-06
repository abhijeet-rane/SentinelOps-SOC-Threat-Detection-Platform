import { useState, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react';

import { ToastContext } from './ToastContext';

const ICONS = {
    success: CheckCircle,
    error: XCircle,
    warning: AlertTriangle,
    info: Info,
};
const COLORS = {
    success: 'var(--green-400)',
    error: 'var(--red-400)',
    warning: 'var(--amber-400)',
    info: 'var(--cyan-400)',
};

let toastId = 0;

export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([]);

    const addToast = useCallback((message, type = 'info', duration = 4000) => {
        const id = ++toastId;
        setToasts(prev => [...prev, { id, message, type }]);
        if (duration > 0) setTimeout(() => removeToast(id), duration);
    }, []);

    const removeToast = (id) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    };

    const toast = useMemo(() => ({
        success: (msg) => addToast(msg, 'success'),
        error: (msg) => addToast(msg, 'error'),
        warning: (msg) => addToast(msg, 'warning'),
        info: (msg) => addToast(msg, 'info'),
    }), [addToast]);

    return (
        <ToastContext.Provider value={toast}>
            {children}
            <div style={{
                position: 'fixed', top: 16, right: 16, zIndex: 9999,
                display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 380,
            }}>
                <AnimatePresence>
                    {toasts.map(t => {
                        const Icon = ICONS[t.type] || Info;
                        return (
                            <motion.div
                                key={t.id}
                                initial={{ opacity: 0, x: 80, scale: 0.9 }}
                                animate={{ opacity: 1, x: 0, scale: 1 }}
                                exit={{ opacity: 0, x: 80, scale: 0.9 }}
                                transition={{ type: 'spring', damping: 20, stiffness: 300 }}
                                style={{
                                    display: 'flex', alignItems: 'center', gap: 10,
                                    padding: '12px 16px', borderRadius: 10,
                                    background: 'var(--bg-elevated)',
                                    border: `1px solid ${COLORS[t.type]}30`,
                                    boxShadow: `0 4px 20px rgba(0,0,0,0.4), 0 0 15px ${COLORS[t.type]}15`,
                                    backdropFilter: 'blur(12px)',
                                    fontSize: '0.82rem', color: 'var(--text-primary)',
                                }}
                            >
                                <Icon size={18} style={{ color: COLORS[t.type], flexShrink: 0 }} />
                                <span style={{ flex: 1 }}>{t.message}</span>
                                <button
                                    onClick={() => removeToast(t.id)}
                                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
                                >
                                    <X size={14} />
                                </button>
                            </motion.div>
                        );
                    })}
                </AnimatePresence>
            </div>
        </ToastContext.Provider>
    );
}


