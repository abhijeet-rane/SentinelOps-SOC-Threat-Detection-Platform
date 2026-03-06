import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
    FileText, Download, Calendar, BarChart3, Shield, Users, CheckCircle,
    AlertTriangle, Loader2, FileSpreadsheet
} from 'lucide-react';
import { api } from '../api';
import { useToast } from '../components/ToastContext';

const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.05 } } };
const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };

const tabs = [
    { id: 'daily', label: 'Daily SOC', icon: BarChart3 },
    { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
    { id: 'analysts', label: 'Analyst Perf', icon: Users },
    { id: 'compliance', label: 'Compliance', icon: Shield },
];

const frameworks = ['NIST', 'ISO27001', 'SOC2'];

export default function Reports() {
    const [tab, setTab] = useState('daily');
    const [loading, setLoading] = useState(false);
    const [data, setData] = useState(null);
    const [framework, setFramework] = useState('NIST');
    const [exporting, setExporting] = useState(null);
    const toast = useToast();

    const [from, setFrom] = useState(() => new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0]);
    const [to, setTo] = useState(() => new Date().toISOString().split('T')[0]);

    const load = useCallback(async () => {
        setLoading(true);
        setData(null);
        try {
            let res;
            switch (tab) {
                case 'daily': res = await api.getDailyReport(from, to); break;
                case 'incidents': res = await api.getIncidentReport(from, to); break;
                case 'analysts': res = await api.getAnalystReport(from, to); break;
                case 'compliance': res = await api.getComplianceReport(from, to, framework); break;
            }
            if (res?.success) setData(res.data);
        } catch (err) {
            console.error('Report load failed:', err);
            toast.error('Failed to load report');
        }
        setLoading(false);
    }, [tab, from, to, framework, toast]);

    useEffect(() => {
        const timer = setTimeout(() => {
            load();
        }, 0);
        return () => clearTimeout(timer);
    }, [load]);

    const handleExport = async (format) => {
        setExporting(format);
        try {
            await api.exportReport(tab, format, from, to, framework);
            toast.success(`${format.toUpperCase()} downloaded`);
        } catch {
            toast.error('Export failed');
        }
        setExporting(null);
    };

    return (
        <motion.div variants={container} initial="hidden" animate="show">
            <motion.div variants={item} className="page-header">
                <div>
                    <h2>Reports & Compliance</h2>
                    <p>Generate, view, and export SOC operational and compliance reports</p>
                </div>
                <div className="flex gap-sm items-center">
                    <button className="btn btn-ghost btn-sm" onClick={() => handleExport('pdf')}
                        disabled={!data || exporting} style={{ color: 'var(--red-400)' }}>
                        {exporting === 'pdf' ? <Loader2 size={14} className="spin" /> : <Download size={14} />} PDF
                    </button>
                    <button className="btn btn-ghost btn-sm" onClick={() => handleExport('excel')}
                        disabled={!data || exporting} style={{ color: 'var(--green-400)' }}>
                        {exporting === 'excel' ? <Loader2 size={14} className="spin" /> : <FileSpreadsheet size={14} />} Excel
                    </button>
                </div>
            </motion.div>

            {/* Tab Bar */}
            <motion.div variants={item} className="flex gap-sm" style={{ marginBottom: 16 }}>
                {tabs.map(t => (
                    <button key={t.id} className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => setTab(t.id)}>
                        <t.icon size={14} /> {t.label}
                    </button>
                ))}
            </motion.div>

            {/* Date Range + Framework */}
            <motion.div variants={item} className="filter-bar">
                <div className="flex gap-sm items-center">
                    <Calendar size={14} style={{ color: 'var(--text-muted)' }} />
                    <input type="date" className="form-select" value={from} onChange={e => setFrom(e.target.value)} />
                    <span style={{ color: 'var(--text-muted)' }}>to</span>
                    <input type="date" className="form-select" value={to} onChange={e => setTo(e.target.value)} />
                    {tab === 'compliance' && (
                        <select className="form-select" value={framework} onChange={e => setFramework(e.target.value)}>
                            {frameworks.map(f => <option key={f} value={f}>{f === 'ISO27001' ? 'ISO 27001' : f === 'SOC2' ? 'SOC 2' : 'NIST CSF'}</option>)}
                        </select>
                    )}
                    <button className="btn btn-primary btn-sm" onClick={load} disabled={loading}>
                        {loading ? <Loader2 size={14} className="spin" /> : 'Generate'}
                    </button>
                </div>
            </motion.div>

            {/* Content */}
            {loading ? (
                <div style={{ padding: 60, textAlign: 'center' }}>
                    <Loader2 size={28} className="spin" style={{ color: 'var(--cyan-400)' }} />
                    <div style={{ marginTop: 10, color: 'var(--text-muted)' }}>Generating report…</div>
                </div>
            ) : data ? (
                <motion.div variants={item}>
                    {tab === 'daily' && <DailyView data={data} />}
                    {tab === 'incidents' && <IncidentView data={data} />}
                    {tab === 'analysts' && <AnalystView data={data} />}
                    {tab === 'compliance' && <ComplianceView data={data} />}
                </motion.div>
            ) : (
                <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>
                    <FileText size={32} style={{ marginBottom: 8 }} />
                    <div>Select a date range and click Generate</div>
                </div>
            )}
        </motion.div>
    );
}

/* ─── KPI Card ─── */
function Kpi({ label, value, accent = 'var(--cyan-400)' }) {
    return (
        <div className="card" style={{ padding: '16px 20px', minWidth: 140, textAlign: 'center' }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: accent, fontFamily: 'var(--font-mono)' }}>{value}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>{label}</div>
        </div>
    );
}

/* ─── Daily SOC Report ─── */
function DailyView({ data }) {
    const k = data.kpis;
    const s = data.slaCompliance;
    return (
        <>
            <div className="flex gap-sm" style={{ flexWrap: 'wrap', marginBottom: 16 }}>
                <Kpi label="Total Alerts" value={k.totalAlerts} />
                <Kpi label="Resolved" value={k.resolvedAlerts} accent="var(--green-400)" />
                <Kpi label="Escalated" value={k.escalatedAlerts} accent="var(--amber-400)" />
                <Kpi label="MTTD" value={`${k.mttdMinutes}m`} accent="var(--purple-400)" />
                <Kpi label="MTTR" value={`${k.mttrMinutes}m`} accent="var(--blue-400)" />
                <Kpi label="FP Rate" value={`${k.falsePositiveRate}%`} accent={k.falsePositiveRate > 20 ? 'var(--red-400)' : 'var(--green-400)'} />
                <Kpi label="SLA Compliance" value={`${s.compliancePercent}%`} accent={s.compliancePercent >= 90 ? 'var(--green-400)' : 'var(--red-400)'} />
                <Kpi label="Logs Ingested" value={data.totalLogsIngested.toLocaleString()} />
                <Kpi label="Playbook Runs" value={data.playbookExecutions} />
                <Kpi label="New Incidents" value={data.newIncidents} accent="var(--red-400)" />
            </div>

            <div className="flex gap-sm" style={{ marginBottom: 16 }}>
                <div className="card" style={{ flex: 1, padding: 16 }}>
                    <h4 style={{ marginBottom: 8 }}>Severity Breakdown</h4>
                    <div className="flex gap-sm">
                        {['Critical', 'High', 'Medium', 'Low'].map(s => (
                            <div key={s} style={{ flex: 1, textAlign: 'center' }}>
                                <div className={`severity-badge ${s.toLowerCase()}`} style={{ display: 'inline-block', marginBottom: 4 }}>{s}</div>
                                <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{data.alertBreakdown[s.toLowerCase()]}</div>
                            </div>
                        ))}
                    </div>
                </div>
                <div className="card" style={{ flex: 1, padding: 16 }}>
                    <h4 style={{ marginBottom: 8 }}>Status Breakdown</h4>
                    <div className="flex gap-sm">
                        {['New', 'InProgress', 'Escalated', 'Resolved', 'Closed'].map(st => (
                            <div key={st} style={{ flex: 1, textAlign: 'center' }}>
                                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>{st}</div>
                                <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                                    {data.alertBreakdown[st.charAt(0).toLowerCase() + st.slice(1)]}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {data.topDetectionRules?.length > 0 && (
                <div className="card">
                    <h4 style={{ padding: '12px 16px 0' }}>Top Detection Rules</h4>
                    <div style={{ overflowX: 'auto' }}>
                        <table className="data-table">
                            <thead><tr><th>Rule</th><th>Severity</th><th>MITRE</th><th>Hits</th></tr></thead>
                            <tbody>
                                {data.topDetectionRules.map((r, i) => (
                                    <tr key={i}>
                                        <td style={{ fontWeight: 600 }}>{r.ruleName}</td>
                                        <td><span className={`severity-badge ${r.severity.toLowerCase()}`}>{r.severity}</span></td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{r.mitreTechnique || '—'}</td>
                                        <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{r.hits}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </>
    );
}

/* ─── Incident Summary ─── */
function IncidentView({ data }) {
    return (
        <>
            <div className="flex gap-sm" style={{ flexWrap: 'wrap', marginBottom: 16 }}>
                <Kpi label="Total Incidents" value={data.totalIncidents} />
                <Kpi label="Open" value={data.openIncidents} accent="var(--amber-400)" />
                <Kpi label="Resolved" value={data.resolvedIncidents} accent="var(--green-400)" />
                <Kpi label="Closed" value={data.closedIncidents} accent="var(--text-muted)" />
                <Kpi label="Avg Resolution" value={`${data.avgResolutionHours}h`} accent="var(--blue-400)" />
            </div>

            <div className="flex gap-sm" style={{ marginBottom: 16 }}>
                <div className="card" style={{ padding: 16 }}>
                    <h4 style={{ marginBottom: 8 }}>Severity Distribution</h4>
                    <div className="flex gap-sm">
                        {['Critical', 'High', 'Medium', 'Low'].map(s => (
                            <div key={s} style={{ textAlign: 'center', flex: 1 }}>
                                <div className={`severity-badge ${s.toLowerCase()}`} style={{ display: 'inline-block', marginBottom: 4 }}>{s}</div>
                                <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{data.severityBreakdown[s.toLowerCase()]}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {data.incidents?.length > 0 && (
                <div className="card">
                    <div style={{ overflowX: 'auto' }}>
                        <table className="data-table">
                            <thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Alerts</th><th>Resolution</th><th>Created</th></tr></thead>
                            <tbody>
                                {data.incidents.map(i => (
                                    <tr key={i.id}>
                                        <td style={{ fontWeight: 600, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i.title}</td>
                                        <td><span className={`severity-badge ${i.severity.toLowerCase()}`}>{i.severity}</span></td>
                                        <td><span className={`status-badge ${i.status.toLowerCase()}`}>{i.status}</span></td>
                                        <td style={{ fontFamily: 'var(--font-mono)' }}>{i.alertCount}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)' }}>{i.resolutionHours != null ? `${i.resolutionHours}h` : '—'}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{new Date(i.createdAt).toLocaleDateString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </>
    );
}

/* ─── Analyst Performance ─── */
function AnalystView({ data }) {
    return data.analysts?.length > 0 ? (
        <div className="card">
            <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Analyst</th><th>Role</th><th>Assigned</th><th>Resolved</th>
                            <th>Escalated</th><th>Avg Time</th><th>SLA %</th><th>Incidents</th>
                        </tr>
                    </thead>
                    <tbody>
                        {data.analysts.map(a => (
                            <tr key={a.id}>
                                <td style={{ fontWeight: 600 }}>{a.name}</td>
                                <td style={{ fontSize: '0.78rem' }}>{a.role}</td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{a.assignedAlerts}</td>
                                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--green-400)' }}>{a.resolvedAlerts}</td>
                                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--amber-400)' }}>{a.escalatedAlerts}</td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{a.avgResolutionMinutes}m</td>
                                <td>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                        <div style={{
                                            width: 60, height: 6, borderRadius: 3, background: 'var(--surface-alt)',
                                            overflow: 'hidden', position: 'relative'
                                        }}>
                                            <div style={{
                                                width: `${a.slaCompliancePercent}%`, height: '100%', borderRadius: 3,
                                                background: a.slaCompliancePercent >= 90 ? 'var(--green-400)' : a.slaCompliancePercent >= 70 ? 'var(--amber-400)' : 'var(--red-400)'
                                            }} />
                                        </div>
                                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{a.slaCompliancePercent}%</span>
                                    </div>
                                </td>
                                <td style={{ fontFamily: 'var(--font-mono)' }}>{a.incidentsWorked}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    ) : (
        <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            <Users size={32} style={{ marginBottom: 8 }} />
            <div>No analyst activity in this period</div>
        </div>
    );
}

/* ─── Compliance Report ─── */
function ComplianceView({ data }) {
    const statusColor = {
        Compliant: 'var(--green-400)', Partial: 'var(--amber-400)', NonCompliant: 'var(--red-400)'
    };
    const statusIcon = {
        Compliant: <CheckCircle size={14} />, Partial: <AlertTriangle size={14} />, NonCompliant: <AlertTriangle size={14} />
    };

    return (
        <>
            <div className="flex gap-sm" style={{ marginBottom: 16, flexWrap: 'wrap' }}>
                <Kpi label="Framework" value={data.frameworkVersion} accent="var(--cyan-400)" />
                <Kpi label="Overall Score" value={`${data.overallScore}%`}
                    accent={data.overallScore >= 80 ? 'var(--green-400)' : data.overallScore >= 50 ? 'var(--amber-400)' : 'var(--red-400)'} />
                <Kpi label="Compliant" value={data.controls.filter(c => c.status === 'Compliant').length} accent="var(--green-400)" />
                <Kpi label="Partial" value={data.controls.filter(c => c.status === 'Partial').length} accent="var(--amber-400)" />
                <Kpi label="Non-Compliant" value={data.controls.filter(c => c.status === 'NonCompliant').length} accent="var(--red-400)" />
            </div>

            <div className="card">
                <div style={{ overflowX: 'auto' }}>
                    <table className="data-table">
                        <thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Status</th><th>Evidence</th></tr></thead>
                        <tbody>
                            {data.controls.map(c => (
                                <tr key={c.controlId}>
                                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{c.controlId}</td>
                                    <td style={{ fontWeight: 500 }}>{c.controlName}</td>
                                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{c.category}</td>
                                    <td>
                                        <span style={{
                                            display: 'inline-flex', alignItems: 'center', gap: 4,
                                            color: statusColor[c.status] || 'var(--text-muted)',
                                            background: `${statusColor[c.status] || 'var(--text-muted)'}15`,
                                            padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600
                                        }}>
                                            {statusIcon[c.status]} {c.status}
                                        </span>
                                    </td>
                                    <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: 300 }}>{c.evidence}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}
