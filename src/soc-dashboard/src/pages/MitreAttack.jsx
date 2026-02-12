import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Loader } from 'lucide-react';
import { api } from '../api';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.08 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const heatColor = (hits) => {
    if (hits === 0) return 'rgba(148,163,184,0.06)';
    if (hits <= 2) return 'rgba(6,182,212,0.2)';
    if (hits <= 5) return 'rgba(245,158,11,0.35)';
    if (hits <= 10) return 'rgba(245,158,11,0.55)';
    return 'rgba(239,68,68,0.55)';
};

export default function MitreAttack() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        (async () => {
            const res = await api.getMitreCoverage();
            if (res.success) setData(res.data);
            setLoading(false);
        })();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center" style={{ height: '60vh' }}>
                <Loader className="spin" size={32} style={{ color: 'var(--cyan-400)' }} />
            </div>
        );
    }

    const matrix = data?.matrix || [];
    const summary = data?.summary || {};

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>MITRE ATT&CK Coverage</h2>
                    <p>Enterprise technique detection heatmap from real alert data</p>
                </div>
            </motion.div>

            {/* Summary Cards */}
            <motion.div variants={item} className="stat-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 24 }}>
                <div className="stat-card info">
                    <div className="stat-value">{summary.totalHits || 0}</div>
                    <div className="stat-label">Total technique hits</div>
                </div>
                <div className="stat-card info">
                    <div className="stat-value" style={{ color: 'var(--cyan-400)' }}>{summary.activeTechniques || 0}</div>
                    <div className="stat-label">Active techniques detected</div>
                </div>
                <div className="stat-card info">
                    <div className="stat-value" style={{ color: 'var(--green-400)' }}>{summary.tacticsCount || 0}</div>
                    <div className="stat-label">ATT&CK tactics covered</div>
                </div>
            </motion.div>

            {/* Heatmap Legend */}
            <motion.div variants={item} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                <span>Heat:</span>
                {[0, 1, 3, 6, 11].map((v, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <div style={{ width: 14, height: 14, borderRadius: 3, background: heatColor(v) }} />
                        <span>{['None', '1-2', '3-5', '6-10', '11+'][i]}</span>
                    </div>
                ))}
            </motion.div>

            {/* MITRE Heatmap Grid */}
            <motion.div variants={item} className="card">
                <div className="card-body" style={{ overflowX: 'auto' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: `180px repeat(${Math.max(...matrix.map(t => (t.techniques?.length || 0)), 1)}, 1fr)`, gap: 4 }}>
                        {matrix.map((tactic, ti) => (
                            <motion.div key={tactic.name} style={{ display: 'contents' }}
                                initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: ti * 0.08 }}>
                                <div style={{
                                    display: 'flex', alignItems: 'center', gap: 8,
                                    padding: '8px 12px', fontWeight: 700, fontSize: '0.75rem',
                                    color: 'var(--text-primary)', background: 'var(--bg-deep)',
                                    borderRadius: 6, whiteSpace: 'nowrap'
                                }}>
                                    <Shield size={13} style={{ color: 'var(--cyan-400)', flexShrink: 0 }} />
                                    {tactic.name}
                                </div>
                                {(tactic.techniques || []).map((tech, idx) => (
                                    <motion.div key={tech.id || idx}
                                        style={{
                                            background: heatColor(tech.hits),
                                            borderRadius: 6, padding: '10px 12px',
                                            border: tech.hits > 0 ? '1px solid rgba(255,255,255,0.05)' : '1px solid transparent',
                                            cursor: 'default', minWidth: 100,
                                        }}
                                        whileHover={{ scale: 1.05 }}
                                        title={`${tech.id} • ${tech.name} • ${tech.hits} hits`}
                                    >
                                        <div style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: 2 }}>{tech.id}</div>
                                        <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.2 }}>{tech.name}</div>
                                        {tech.hits > 0 && (
                                            <div style={{ fontSize: '0.75rem', fontWeight: 700, marginTop: 4, color: tech.hits > 5 ? 'var(--red-400)' : 'var(--amber-400)' }}>
                                                {tech.hits} hit{tech.hits !== 1 ? 's' : ''}
                                            </div>
                                        )}
                                    </motion.div>
                                ))}
                            </motion.div>
                        ))}
                    </div>
                </div>
            </motion.div>
        </motion.div>
    );
}
