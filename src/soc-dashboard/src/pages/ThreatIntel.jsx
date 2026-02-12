import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Shield, Plus, Search, Upload, Database, Globe, Hash, Mail, Link,
    AlertTriangle, Target, TrendingUp, Activity, Eye, ToggleLeft, ToggleRight,
    Trash2, RefreshCw, Loader2, ChevronDown, X, Zap
} from 'lucide-react';
import {
    PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { api } from '../api';

const INDICATOR_ICONS = { IpAddress: Globe, Domain: Link, FileHash: Hash, Url: Link, Email: Mail };
const THREAT_COLORS = { Critical: '#ef4444', High: '#f59e0b', Medium: '#06b6d4', Low: '#10b981', Informational: '#6b7280' };

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.05 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '10px 14px', fontSize: '0.8rem' }}>
            <p style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>{label}</p>
            {payload.map((p, i) => (
                <p key={i} style={{ color: p.color || 'var(--text-secondary)' }}>{p.name}: <strong>{p.value}</strong></p>
            ))}
        </div>
    );
};

function EnrichmentPanel() {
    const [value, setValue] = useState('');
    const [type, setType] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleEnrich = async () => {
        if (!value.trim()) return;
        setLoading(true);
        const res = await api.enrichValue(value.trim(), type || undefined);
        setResult(res?.data || null);
        setLoading(false);
    };

    return (
        <motion.div variants={item} className="card" style={{ marginBottom: 20 }}>
            <div style={{ padding: 22 }}>
                <h3 style={{ marginBottom: 16 }}>
                    <Search size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />
                    IOC Enrichment Lookup
                </h3>
                <div className="flex gap-sm items-end">
                    <div style={{ flex: 1 }}>
                        <label className="form-label">Value (IP, Domain, Hash, URL, or Email)</label>
                        <input type="text" className="form-input" placeholder="192.168.1.105 or evil-domain.com or md5hash..."
                            value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleEnrich()} />
                    </div>
                    <div style={{ width: 160 }}>
                        <label className="form-label">Type (auto-detect)</label>
                        <select className="form-select" value={type} onChange={e => setType(e.target.value)}>
                            <option value="">Auto-detect</option>
                            <option value="IpAddress">IP Address</option>
                            <option value="Domain">Domain</option>
                            <option value="FileHash">File Hash</option>
                            <option value="Url">URL</option>
                            <option value="Email">Email</option>
                        </select>
                    </div>
                    <motion.button className="btn btn-primary" onClick={handleEnrich} disabled={loading}
                        whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} style={{ height: 40 }}>
                        {loading ? <Loader2 size={14} className="spin" /> : <Zap size={14} />} Enrich
                    </motion.button>
                </div>

                <AnimatePresence>
                    {result && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
                            style={{ marginTop: 16 }}>
                            <div style={{
                                padding: 16, borderRadius: 10,
                                background: result.isMalicious ? 'rgba(239,68,68,0.08)' : 'rgba(16,185,129,0.08)',
                                border: `1px solid ${result.isMalicious ? 'var(--red-400)' : 'var(--green-400)'}`,
                            }}>
                                <div className="flex items-center gap-sm" style={{ marginBottom: 12 }}>
                                    {result.isMalicious
                                        ? <AlertTriangle size={18} color="var(--red-400)" />
                                        : <Shield size={18} color="var(--green-400)" />
                                    }
                                    <strong style={{ color: result.isMalicious ? 'var(--red-400)' : 'var(--green-400)' }}>
                                        {result.isMalicious ? `⚠ MALICIOUS — ${result.matchCount} match(es)` : '✓ No threats found'}
                                    </strong>
                                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                                        Query: <code>{result.queryValue}</code> ({result.queryType})
                                    </span>
                                </div>

                                {result.matches?.length > 0 && (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                        {result.matches.map((m, i) => (
                                            <div key={i} style={{ background: 'var(--bg-surface)', padding: 12, borderRadius: 8, fontSize: '0.82rem' }}>
                                                <div className="flex gap-md flex-wrap">
                                                    <span><strong>Source:</strong> {m.source}</span>
                                                    <span><strong>Type:</strong> {m.threatType}</span>
                                                    <span className={`severity-badge ${m.threatLevel.toLowerCase()}`}>{m.threatLevel}</span>
                                                    <span><strong>Confidence:</strong> {m.confidenceScore}%</span>
                                                </div>
                                                {m.description && <div style={{ marginTop: 6, color: 'var(--text-secondary)' }}>{m.description}</div>}
                                                <div className="flex gap-sm flex-wrap" style={{ marginTop: 6 }}>
                                                    {m.tags && m.tags.split(',').map(tag => (
                                                        <span key={tag} style={{ background: 'var(--bg-deep)', padding: '1px 8px', borderRadius: 4, fontSize: '0.7rem', color: 'var(--cyan-400)' }}>
                                                            {tag.trim()}
                                                        </span>
                                                    ))}
                                                    {m.associatedCVEs && <span style={{ color: 'var(--amber-400)', fontSize: '0.72rem' }}>CVEs: {m.associatedCVEs}</span>}
                                                    {m.mitreTechniques && <span style={{ color: 'var(--purple-400)', fontSize: '0.72rem' }}>MITRE: {m.mitreTechniques}</span>}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </motion.div>
    );
}

function AddIndicatorModal({ onClose, onCreated }) {
    const [form, setForm] = useState({
        indicatorType: 'IpAddress', value: '', source: 'Manual', confidenceScore: 50,
        threatType: '', threatLevel: 'Medium', description: '', tags: '',
        associatedCVEs: '', mitreTechniques: '', geoCountry: '', asn: '',
    });
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        const res = await api.createThreatIntel(form);
        if (res?.success) { onCreated(); onClose(); }
        setLoading(false);
    };

    const set = (key) => (e) => setForm({ ...form, [key]: key === 'confidenceScore' ? parseInt(e.target.value) : e.target.value });

    return (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            onClick={onClose}>
            <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
                style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 16, padding: 28, width: 600, maxHeight: '80vh', overflowY: 'auto' }}
                onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between" style={{ marginBottom: 20 }}>
                    <h3><Plus size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />Add Indicator</h3>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><X size={18} /></button>
                </div>
                <form onSubmit={handleSubmit}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                        <div className="form-group">
                            <label className="form-label">Type</label>
                            <select className="form-select" value={form.indicatorType} onChange={set('indicatorType')}>
                                <option value="IpAddress">IP Address</option>
                                <option value="Domain">Domain</option>
                                <option value="FileHash">File Hash</option>
                                <option value="Url">URL</option>
                                <option value="Email">Email</option>
                            </select>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Value</label>
                            <input className="form-input" placeholder="e.g. 192.168.1.1" value={form.value} onChange={set('value')} required />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Source</label>
                            <input className="form-input" placeholder="e.g. AbuseIPDB" value={form.source} onChange={set('source')} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Confidence (0–100)</label>
                            <input type="number" className="form-input" min={0} max={100} value={form.confidenceScore} onChange={set('confidenceScore')} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Threat Type</label>
                            <select className="form-select" value={form.threatType} onChange={set('threatType')}>
                                <option value="">Select...</option>
                                <option value="Malware">Malware</option>
                                <option value="C2">C2 (Command & Control)</option>
                                <option value="Phishing">Phishing</option>
                                <option value="Botnet">Botnet</option>
                                <option value="Scanner">Scanner</option>
                                <option value="APT">APT</option>
                                <option value="Ransomware">Ransomware</option>
                                <option value="Trojan">Trojan</option>
                                <option value="Cryptomining">Cryptomining</option>
                                <option value="Brute Force">Brute Force</option>
                            </select>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Threat Level</label>
                            <select className="form-select" value={form.threatLevel} onChange={set('threatLevel')}>
                                <option value="Critical">Critical</option>
                                <option value="High">High</option>
                                <option value="Medium">Medium</option>
                                <option value="Low">Low</option>
                                <option value="Informational">Informational</option>
                            </select>
                        </div>
                        <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                            <label className="form-label">Description</label>
                            <input className="form-input" placeholder="Why is this indicator malicious?" value={form.description} onChange={set('description')} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Tags (comma-separated)</label>
                            <input className="form-input" placeholder="ransomware,lockbit" value={form.tags} onChange={set('tags')} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">MITRE Techniques</label>
                            <input className="form-input" placeholder="T1566,T1059" value={form.mitreTechniques} onChange={set('mitreTechniques')} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">CVEs</label>
                            <input className="form-input" placeholder="CVE-2023-38831" value={form.associatedCVEs} onChange={set('associatedCVEs')} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Country</label>
                            <input className="form-input" placeholder="RU, CN, US..." value={form.geoCountry} onChange={set('geoCountry')} />
                        </div>
                    </div>
                    <div className="flex gap-sm justify-end" style={{ marginTop: 18 }}>
                        <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
                        <button type="submit" className="btn btn-primary" disabled={loading}>
                            {loading ? <Loader2 size={14} className="spin" /> : <Plus size={14} />} Add Indicator
                        </button>
                    </div>
                </form>
            </motion.div>
        </div>
    );
}

export default function ThreatIntel() {
    const [indicators, setIndicators] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState({ page: 1, pageSize: 20 });
    const [total, setTotal] = useState(0);
    const [showAdd, setShowAdd] = useState(false);
    const [seeding, setSeeding] = useState(false);

    const load = useCallback(async () => {
        setLoading(true);
        const [indRes, statsRes] = await Promise.all([
            api.getThreatIntel(filter),
            api.getThreatIntelStats(),
        ]);
        if (indRes?.data) {
            setIndicators(indRes.data.items || []);
            setTotal(indRes.data.total || 0);
        }
        if (statsRes?.data) setStats(statsRes.data);
        setLoading(false);
    }, [filter]);

    useEffect(() => { load(); }, [load]);

    const handleSeed = async () => {
        setSeeding(true);
        await api.seedThreatIntel();
        await load();
        setSeeding(false);
    };

    const handleToggle = async (id) => {
        await api.toggleThreatIntel(id);
        load();
    };

    const handleDelete = async (id) => {
        await api.deleteThreatIntel(id);
        load();
    };

    const updateFilter = (key, val) => setFilter(prev => ({ ...prev, [key]: val, page: 1 }));

    const typeChartData = stats ? Object.entries(stats.byType || {}).map(([name, value]) => ({ name, value })) : [];
    const levelChartData = stats ? Object.entries(stats.byThreatLevel || {}).map(([name, value]) => ({ name, value, fill: THREAT_COLORS[name] || '#6b7280' })) : [];
    const sourceChartData = stats ? Object.entries(stats.bySource || {}).map(([name, count]) => ({ name, count })) : [];

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Threat Intelligence</h2>
                    <p>IOC management, enrichment, and threat feed integration</p>
                </div>
                <div className="flex gap-sm">
                    <button className="btn btn-ghost btn-sm" onClick={handleSeed} disabled={seeding}>
                        {seeding ? <Loader2 size={14} className="spin" /> : <Database size={14} />} Seed Demo Data
                    </button>
                    <button className="btn btn-primary btn-sm" onClick={() => setShowAdd(true)}>
                        <Plus size={14} /> Add IOC
                    </button>
                </div>
            </motion.div>

            {/* Stats Cards */}
            {stats && (
                <motion.div variants={item} className="stat-grid">
                    <div className="stat-card info">
                        <div className="stat-icon"><Database size={22} /></div>
                        <div className="stat-value">{stats.totalIndicators}</div>
                        <div className="stat-label">Total Indicators</div>
                    </div>
                    <div className="stat-card medium">
                        <div className="stat-icon"><Shield size={22} /></div>
                        <div className="stat-value">{stats.activeIndicators}</div>
                        <div className="stat-label">Active IOCs</div>
                    </div>
                    <div className="stat-card critical">
                        <div className="stat-icon"><Target size={22} /></div>
                        <div className="stat-value">{stats.totalMatches}</div>
                        <div className="stat-label">Total Matches</div>
                    </div>
                    <div className="stat-card high">
                        <div className="stat-icon"><Activity size={22} /></div>
                        <div className="stat-value">{stats.matchesLast24h}</div>
                        <div className="stat-label">Matches (24h)</div>
                    </div>
                    <div className="stat-card low">
                        <div className="stat-icon"><AlertTriangle size={22} /></div>
                        <div className="stat-value">{stats.expiredIndicators}</div>
                        <div className="stat-label">Expired</div>
                    </div>
                </motion.div>
            )}

            {/* Enrichment Panel */}
            <EnrichmentPanel />

            {/* Charts */}
            {stats && (
                <motion.div variants={item} className="chart-grid" style={{ marginBottom: 20 }}>
                    <div className="chart-card">
                        <h3>By Threat Level</h3>
                        <ResponsiveContainer width="100%" height={220}>
                            <PieChart>
                                <Pie data={levelChartData} cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={4} dataKey="value" stroke="none">
                                    {levelChartData.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
                                </Pie>
                                <Tooltip content={<CustomTooltip />} />
                                <Legend wrapperStyle={{ fontSize: 12 }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="chart-card">
                        <h3>By Source Feed</h3>
                        <ResponsiveContainer width="100%" height={220}>
                            <BarChart data={sourceChartData} barSize={28}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
                                <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} tickLine={false} angle={-20} textAnchor="end" height={50} />
                                <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} />
                                <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} name="IOCs" />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </motion.div>
            )}

            {/* Filter Bar */}
            <motion.div variants={item} className="filter-bar">
                <select className="form-select" value={filter.indicatorType || ''} onChange={e => updateFilter('indicatorType', e.target.value)}>
                    <option value="">All Types</option>
                    <option value="IpAddress">IP Address</option>
                    <option value="Domain">Domain</option>
                    <option value="FileHash">File Hash</option>
                    <option value="Url">URL</option>
                    <option value="Email">Email</option>
                </select>
                <select className="form-select" value={filter.threatLevel || ''} onChange={e => updateFilter('threatLevel', e.target.value)}>
                    <option value="">All Levels</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <select className="form-select" value={filter.sortBy || 'CreatedAt'} onChange={e => updateFilter('sortBy', e.target.value)}>
                    <option value="CreatedAt">Newest</option>
                    <option value="hitCount">Most Matched</option>
                    <option value="confidenceScore">Confidence</option>
                    <option value="value">Value</option>
                </select>
                <div style={{ position: 'relative', flex: 1 }}>
                    <input type="text" className="form-input" placeholder="Search IOCs..." style={{ paddingLeft: 34 }}
                        onChange={e => updateFilter('searchValue', e.target.value)} />
                    <Search size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{total}</strong> indicators
                </div>
            </motion.div>

            {/* IOC Table */}
            <motion.div variants={item} className="card">
                {loading ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                        <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Loading indicators...</div>
                    </div>
                ) : indicators.length === 0 ? (
                    <div style={{ padding: 40, textAlign: 'center' }}>
                        <Database size={32} style={{ color: 'var(--text-muted)', marginBottom: 8 }} />
                        <div style={{ color: 'var(--text-muted)' }}>No indicators found. Click "Seed Demo Data" to populate.</div>
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Indicator</th>
                                    <th>Type</th>
                                    <th>Level</th>
                                    <th>Threat</th>
                                    <th>Source</th>
                                    <th>Confidence</th>
                                    <th>Hits</th>
                                    <th>Tags</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {indicators.map((ind, i) => {
                                    const Icon = INDICATOR_ICONS[ind.indicatorType] || Globe;
                                    return (
                                        <motion.tr key={ind.id}
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: ind.isActive ? 1 : 0.45 }}
                                            transition={{ delay: i * 0.03 }}
                                        >
                                            <td>
                                                <div className="flex items-center gap-sm">
                                                    <Icon size={14} color="var(--cyan-400)" />
                                                    <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                                                        {ind.value}
                                                    </span>
                                                </div>
                                                {ind.geoCountry && <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>🌍 {ind.geoCountry}{ind.asn ? ` · ${ind.asn}` : ''}</div>}
                                            </td>
                                            <td style={{ fontSize: '0.78rem' }}>{ind.indicatorType}</td>
                                            <td><span className={`severity-badge ${ind.threatLevel.toLowerCase()}`}>{ind.threatLevel}</span></td>
                                            <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{ind.threatType}</td>
                                            <td style={{ fontSize: '0.78rem' }}>{ind.source}</td>
                                            <td>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                    <div style={{ background: 'var(--bg-deep)', borderRadius: 6, height: 6, width: 50, overflow: 'hidden' }}>
                                                        <div style={{
                                                            height: '100%', borderRadius: 6, width: `${ind.confidenceScore}%`,
                                                            background: ind.confidenceScore >= 80 ? 'var(--red-400)' : ind.confidenceScore >= 50 ? 'var(--amber-400)' : 'var(--green-400)',
                                                        }} />
                                                    </div>
                                                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{ind.confidenceScore}%</span>
                                                </div>
                                            </td>
                                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', fontWeight: ind.hitCount > 0 ? 700 : 400, color: ind.hitCount > 0 ? 'var(--amber-400)' : 'var(--text-muted)' }}>
                                                {ind.hitCount}
                                            </td>
                                            <td>
                                                <div className="flex gap-sm flex-wrap" style={{ maxWidth: 150 }}>
                                                    {ind.tags?.split(',').slice(0, 3).map(tag => (
                                                        <span key={tag} style={{ background: 'var(--bg-deep)', padding: '1px 6px', borderRadius: 4, fontSize: '0.65rem', color: 'var(--cyan-400)' }}>
                                                            {tag.trim()}
                                                        </span>
                                                    ))}
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex gap-sm">
                                                    <button className="btn btn-ghost btn-sm" title="Toggle" onClick={() => handleToggle(ind.id)}
                                                        style={{ color: ind.isActive ? 'var(--green-400)' : 'var(--text-muted)' }}>
                                                        {ind.isActive ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}
                                                    </button>
                                                    <button className="btn btn-ghost btn-sm" title="Delete" onClick={() => handleDelete(ind.id)}
                                                        style={{ color: 'var(--red-400)' }}>
                                                        <Trash2 size={14} />
                                                    </button>
                                                </div>
                                            </td>
                                        </motion.tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </motion.div>

            {/* Top Matched IOCs */}
            {stats?.topMatched?.length > 0 && (
                <motion.div variants={item} className="card" style={{ marginTop: 20 }}>
                    <div className="card-header">
                        <h3><Target size={16} style={{ display: 'inline', verticalAlign: -3, marginRight: 8 }} />Top Matched IOCs</h3>
                    </div>
                    <div className="card-body" style={{ padding: 0 }}>
                        <table className="data-table">
                            <thead><tr><th>Indicator</th><th>Type</th><th>Threat Level</th><th>Hit Count</th><th>Last Match</th></tr></thead>
                            <tbody>
                                {stats.topMatched.map(t => (
                                    <tr key={t.id}>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{t.value}</td>
                                        <td>{t.indicatorType}</td>
                                        <td><span className={`severity-badge ${t.threatLevel.toLowerCase()}`}>{t.threatLevel}</span></td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--amber-400)' }}>{t.hitCount}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                            {t.lastMatchedAt ? new Date(t.lastMatchedAt).toLocaleString() : '—'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </motion.div>
            )}

            {showAdd && <AddIndicatorModal onClose={() => setShowAdd(false)} onCreated={load} />}
        </motion.div>
    );
}
