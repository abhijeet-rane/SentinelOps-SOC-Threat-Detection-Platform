import { useEffect, useState } from 'react';
import * as stream from '../alertStream';

/**
 * Subscribe to real-time alerts from the SignalR hub. Starts the connection
 * on first use, keeps a rolling buffer of the most recent N alerts, and
 * exposes live status + presence counters.
 *
 *   const { alerts, status, userCount, latest } = useAlertStream(20);
 */
export function useAlertStream(limit = 25) {
    const [alerts, setAlerts]         = useState([]);
    const [status, setStatus]         = useState('connecting');
    const [userCount, setUserCount]   = useState(0);
    const [latest, setLatest]         = useState(null);

    useEffect(() => {
        stream.start();

        const offAlert = stream.onAlert((a) => {
            setAlerts((prev) => [a, ...prev].slice(0, limit));
            setLatest(a);
        });
        const offPresence = stream.onPresence((data) => setUserCount(data?.userCount ?? 0));
        const offStatus = stream.onStatus((s) => setStatus(s));

        return () => {
            offAlert();
            offPresence();
            offStatus();
        };
    }, [limit]);

    return { alerts, status, userCount, latest };
}
