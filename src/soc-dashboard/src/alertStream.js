// ───────────────────────────────────────────────────────────────────────────
// SignalR live-alert stream. Connects to /hubs/alerts with the stored JWT,
// auto-reconnects with exponential backoff, and exposes a pub-sub API for
// React components to subscribe to alerts without each one owning a connection.
// ───────────────────────────────────────────────────────────────────────────
import { HubConnectionBuilder, LogLevel, HttpTransportType } from '@microsoft/signalr';
import { getToken } from './api';

const HUB_URL = 'http://localhost:5101/hubs/alerts';

// Server event names — kept in lock-step with AlertHub.Events in the .NET side.
const EVT = {
    NEW: 'alert:new',
    BATCH: 'alert:batch',
    PRESENCE: 'presence:online',
};

let connection = null;
let startingPromise = null;

const listeners = {
    alert: new Set(),      // (alert) => void
    presence: new Set(),   // ({userCount}) => void
    status: new Set(),     // ('connecting'|'connected'|'reconnecting'|'disconnected', reason?) => void
};

function fire(bucket, ...args) {
    for (const fn of listeners[bucket]) {
        try { fn(...args); } catch { /* swallow listener errors */ }
    }
}

function buildConnection() {
    return new HubConnectionBuilder()
        .withUrl(HUB_URL, {
            accessTokenFactory: () => getToken() ?? '',
            transport: HttpTransportType.WebSockets | HttpTransportType.LongPolling,
        })
        // Exponential backoff: 0 → 2s → 10s → 30s → 60s … then cap at 60s.
        .withAutomaticReconnect({
            nextRetryDelayInMilliseconds: (ctx) => {
                const elapsed = ctx.elapsedMilliseconds;
                if (elapsed < 60_000) return Math.min(30_000, 2_000 * Math.pow(2, ctx.previousRetryCount));
                return 60_000;
            },
        })
        .configureLogging(LogLevel.Warning)
        .build();
}

/** Start or reuse the singleton connection. Safe to call repeatedly. */
export async function start() {
    if (!getToken()) return null;              // not logged in
    if (connection && connection.state === 'Connected') return connection;
    if (startingPromise) return startingPromise;

    connection = buildConnection();

    connection.onreconnecting((err) => fire('status', 'reconnecting', err?.message));
    connection.onreconnected(() => fire('status', 'connected'));
    connection.onclose((err) => {
        fire('status', 'disconnected', err?.message);
        connection = null;
        startingPromise = null;
    });

    connection.on(EVT.NEW, (alert) => fire('alert', alert));
    connection.on(EVT.BATCH, (payload) => {
        if (Array.isArray(payload?.alerts)) payload.alerts.forEach((a) => fire('alert', a));
    });
    connection.on(EVT.PRESENCE, (data) => fire('presence', data));

    fire('status', 'connecting');
    startingPromise = connection.start()
        .then(() => { fire('status', 'connected'); return connection; })
        .catch((err) => {
            fire('status', 'disconnected', err?.message);
            startingPromise = null;
            connection = null;
            return null;
        });

    return startingPromise;
}

/** Gracefully tear down. Called on logout so the next user gets a fresh conn. */
export async function stop() {
    if (connection) {
        try { await connection.stop(); } catch { /* ignore */ }
        connection = null;
        startingPromise = null;
    }
}

export function onAlert(fn)    { listeners.alert.add(fn);    return () => listeners.alert.delete(fn); }
export function onPresence(fn) { listeners.presence.add(fn); return () => listeners.presence.delete(fn); }
export function onStatus(fn)   { listeners.status.add(fn);   return () => listeners.status.delete(fn); }

export function getState() {
    return connection?.state ?? 'Disconnected';
}
