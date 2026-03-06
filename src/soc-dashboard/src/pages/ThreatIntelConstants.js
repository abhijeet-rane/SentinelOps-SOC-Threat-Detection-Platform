import { Globe, Hash, Mail, Link } from 'lucide-react';

export const INDICATOR_ICONS = { IpAddress: Globe, Domain: Link, FileHash: Hash, Url: Link, Email: Mail };
export const THREAT_COLORS = { Critical: '#ef4444', High: '#f59e0b', Medium: '#06b6d4', Low: '#10b981', Informational: '#6b7280' };

export const container = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.05 } } };
export const item = { hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } };
