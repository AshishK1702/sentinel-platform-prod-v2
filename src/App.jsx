import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
    Shield, AlertTriangle, Activity, Database, FileText, Lock, User, Terminal, 
    Globe, Download, Zap, RefreshCw, Trash2, Plus, Briefcase, Building2, Mail, 
    ArrowLeft, Calendar, Layers, BarChart3, Lightbulb, CheckCircle, TrendingUp, 
    TrendingDown, Search, Clock, Map, Server, CheckSquare, AlertOctagon, Ban, 
    ThumbsUp, Check, LogOut
} from 'lucide-react';
import { 
    ResponsiveContainer, PieChart, Pie, Cell, RadarChart, PolarGrid, 
    PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip, Legend, LineChart, 
    Line, BarChart, Bar, XAxis, YAxis, CartesianGrid 
} from 'recharts';
import { initializeApp } from 'firebase/app';
import { 
    getAuth, onAuthStateChanged, createUserWithEmailAndPassword, 
    signInWithEmailAndPassword, signOut, updateProfile, sendPasswordResetEmail 
} from 'firebase/auth';
import { 
    getFirestore, collection, addDoc, setDoc, getDoc, updateDoc, query, 
    onSnapshot, doc, deleteDoc, serverTimestamp, orderBy, writeBatch, limit
} from 'firebase/firestore'; 

// --- CONFIGURATION ---
const firebaseConfig = {
    apiKey: "AIzaSyCY79omhIz4y0meZdz6bEyuoajHY6hL2Rw",
    authDomain: "sentinel-cyber.firebaseapp.com",
    projectId: "sentinel-cyber",
    storageBucket: "sentinel-cyber.firebasestorage.app",
    messagingSenderId: "328311767668",
    appId: "1:328311767668:web:915f82d081784227e54721",
    measurementId: "G-HTNYJ2N8HK"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const appId = "production-v1"; 

// Base URL for backend API (local/dev falls back to localhost)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';


// --- PERFORMANCE CONSTANTS ---
// Limit the number of records displayed in the tables/terminal for virtualization effect.
const DISPLAY_LOGS_LIMIT = 1000; // Increased limit per user request for visible filtered data
// --- END PERFORMANCE CONSTANTS ---

// Firestore paths
const getConnectionRef = (userId) => doc(db, 'artifacts', appId, 'users', userId, 'config', 'connection');
const getUserLogsCollectionRef = (userId) => collection(db, 'artifacts', appId, 'users', userId, 'logs');
const getUserRulesCollectionRef = (userId) => collection(db, 'artifacts', appId, 'users', userId, 'rules');

// --- UTILITIES ---
const PATTERNS = {
    SQL_INJECTION: /(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*(--|\bFROM\b)|'(\s)*(=|OR|AND)|"(\s)*(=|OR|AND))/i,
    XSS: /(<script>|javascript:|on(load|click|error|mouseover)=|%3Cscript%3E)/i,
    BRUTE_FORCE: /(failed login|invalid password|access denied|authentication failure)/i,
    PII_EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    PII_CREDIT_CARD: /\b(?:\d{4}[- ]?){3}\d{4}\b/,
    TRAVERSAL: /(\.\.\/|\.\.\\)/,
    DATE_EXTRACT: /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})|(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})|(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2})/i
};

const analyzeLogLine = (line, source = 'manual', timestampOverride = null) => {
    let generationTime = timestampOverride ? new Date(timestampOverride) : new Date();
    
    if (!timestampOverride) {
        const dateMatch = line.match(PATTERNS.DATE_EXTRACT);
        if (dateMatch) {
            const parsed = new Date(dateMatch[0]);
            if (!isNaN(parsed.getTime())) generationTime = parsed;
        }
    }

    let severity = 'Low';
    let threatType = 'Clean';
    let compliance = [];
    
    if (PATTERNS.SQL_INJECTION.test(line)) { severity = 'Critical'; threatType = 'SQL Injection'; compliance.push('OWASP Top 10'); } 
    else if (PATTERNS.XSS.test(line)) { severity = 'High'; threatType = 'XSS'; compliance.push('OWASP Top 10'); } 
    else if (PATTERNS.BRUTE_FORCE.test(line)) { severity = 'Medium'; threatType = 'Brute Force Attempt'; } 
    else if (PATTERNS.TRAVERSAL.test(line)) { severity = 'High'; threatType = 'Path Traversal'; }

    if (PATTERNS.PII_EMAIL.test(line)) { compliance.push('GDPR'); if (severity === 'Low') severity = 'Medium'; if (threatType === 'Clean') threatType = 'Data Leakage (Email)'; }
    if (PATTERNS.PII_CREDIT_CARD.test(line)) { compliance.push('PCI-DSS'); severity = 'Critical'; threatType = 'Data Leakage (Credit Card)'; }
    if (/\b(password|passwd|secret|key)\s*[:=]\s*\S+/i.test(line)) { severity = 'High'; threatType = 'Credential Exposure'; compliance.push('ISO 27001'); }

    const ipMatch = line.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/);
    const ip = ipMatch ? ipMatch[0] : 'Unknown';
    
    // Status can be 'New', 'Investigating', 'Closed - Fixed', 'Closed - Benign', or 'Blocked'
    return {
        // ID is not set here, it will be the Firestore doc ID
        raw: line,
        timestamp: generationTime.toISOString(),
        logGenerationTime: generationTime.toISOString(),
        severity,
        type: threatType,
        compliance,
        source,
        ip,
        status: 'New' 
    };
};

// Function to deterministically simulate geolocation based on IP
const getSimulatedGeolocation = (ip) => {
    if (ip === 'Unknown') return { country: 'N/A', city: 'N/A' };
    
    const parts = ip.split('.').map(p => parseInt(p, 10));
    
    // Simple mapping based on IP segment ranges for simulation variety
    let country, city;
    if (parts[0] % 5 === 0) {
        country = 'China'; city = parts[1] % 2 === 0 ? 'Beijing' : 'Shanghai';
    } else if (parts[0] % 5 === 1) {
        country = 'Brazil'; city = parts[2] % 2 === 0 ? 'Sao Paulo' : 'Rio de Janeiro';
    } else if (parts[0] % 5 === 2) {
        country = 'USA'; city = parts[3] % 2 === 0 ? 'New York' : 'San Francisco';
    } else if (parts[0] % 5 === 3) {
        country = 'Russia'; city = parts[1] % 3 === 0 ? 'Moscow' : 'St. Petersburg';
    } else {
        country = 'Germany'; city = parts[2] % 3 === 0 ? 'Berlin' : 'Munich';
    }

    return { country, city };
};

const calculateAnalytics = (logs) => {
    const total = logs.length;
    const critical = logs.filter(l => l.severity === 'Critical').length;
    const high = logs.filter(l => l.severity === 'High').length;
    const medium = logs.filter(l => l.severity === 'Medium').length;
    const low = logs.filter(l => l.severity === 'Low').length;

    const complianceScore = total > 0 ? Math.round(((total - logs.filter(l => l.compliance.length > 0).length) / total) * 100) : 100;
    
    const now = new Date();
    const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const currentPeriod = logs.filter(l => new Date(l.timestamp) >= oneWeekAgo);
    const velocity = logs.length > 0 ? (currentPeriod.length / logs.length) * 100 : 0;

    const heatmapData = Array(7).fill(null).map(() => Array(24).fill(0));
    logs.forEach(log => {
        const d = new Date(log.timestamp);
        if(!isNaN(d)) heatmapData[d.getDay()][d.getHours()]++;
    });

    const ipData = logs.reduce((acc, log) => {
        if (log.ip !== 'Unknown' && log.severity !== 'Clean') {
            acc[log.ip] = acc[log.ip] || { count: 0, critical: 0, high: 0 };
            acc[log.ip].count++;
            if (log.severity === 'Critical') acc[log.ip].critical++;
            if (log.severity === 'High') acc[log.ip].high++;
        }
        return acc;
    }, {});
    
    // Calculate details for ALL risky IPs
    const allRiskyAssets = Object.entries(ipData).map(([ip, data]) => {
        // Calculate score based on total count and critical count
        const score = data.count * 5 + data.critical * 10; 
        return {
            ip,
            score,
            count: data.count,
            critical: data.critical,
            high: data.high,
            action: score >= 15 ? 'IMMEDIATE BLOCK' : (score >= 5 ? 'INVESTIGATE' : 'MONITOR'),
        };
    }).sort((a, b) => b.score - a.score); 

    // Top 5 slice for the dashboard widget
    const top5RiskyAssets = allRiskyAssets.slice(0, 5);

    // Filter IPs that appeared multiple times for the dashboard IP chart
    const topIPsChart = top5RiskyAssets.map(a => ({ ip: a.ip, count: a.count }));

    // Compliance Timeline
    const timelineData = logs.reduce((acc, log) => {
        const dateKey = new Date(log.timestamp).toISOString().split('T')[0];
        if (!acc[dateKey]) acc[dateKey] = { date: dateKey, gdpr: 0, pci: 0 };
        if (log.compliance.includes('GDPR')) acc[dateKey].gdpr++;
        if (log.compliance.includes('PCI-DSS')) acc[dateKey].pci++;
        return acc;
    }, {});
    const complianceTimeline = Object.values(timelineData).sort((a, b) => new Date(a.date) - new Date(b.date));

    // Log Ingestion Trend (New)
    const ingestionData = logs.reduce((acc, log) => {
        const dateKey = new Date(log.timestamp).toISOString().split('T')[0];
        if (!acc[dateKey]) acc[dateKey] = { date: dateKey, total: 0 };
        acc[dateKey].total++;
        return acc;
    }, {});
    const logTrend = Object.values(ingestionData).sort((a, b) => new Date(a.date) - new Date(b.date));


    const typeCount = logs.reduce((acc, curr) => { acc[curr.type] = (acc[curr.type] || 0) + 1; return acc; }, {});
    const pieData = Object.keys(typeCount).map(k => ({ name: k, value: typeCount[k] }));

    // Risk Radar Data (Based on total count of violations)
    const gdprCount = logs.filter(l => l.compliance.includes('GDPR')).length;
    const pciCount = logs.filter(l => l.compliance.includes('PCI-DSS')).length;
    const owaspCount = logs.filter(l => l.compliance.includes('OWASP Top 10')).length;
    
    const riskRadarData = [
        { subject: 'SQLi', A: typeCount['SQL Injection'] * 15 || 5, fullMark: 100 },
        { subject: 'XSS', A: typeCount['XSS'] * 15 || 5, fullMark: 100 },
        { subject: 'GDPR', A: gdprCount * 10 || 5, fullMark: 100 },
        { subject: 'Auth', A: typeCount['Brute Force Attempt'] * 10 || 5, fullMark: 100 },
        { subject: 'PII', A: (gdprCount + pciCount) * 5 || 5, fullMark: 100 },
    ];

    // Filter all risky IPs that need explicit blocking/investigation
    const ipsNeedingAction = allRiskyAssets.filter(a => a.score >= 5).length;
    
    // Triage Status Chart Data
    const triageData = Object.entries(logs.reduce((acc, l) => {
        const statusKey = l.status.split(' - ')[0] || l.status; // Group closed items
        acc[statusKey] = (acc[statusKey] || 0) + 1;
        return acc;
    }, { New: 0, Investigating: 0, Blocked: 0, 'Closed - Fixed': 0, 'Closed - Benign': 0 })).map(([name, count]) => ({
        name,
        count
    }));


    return { 
        total, critical, high, medium, low, complianceScore, velocity, mttdMinutes: 12, 
        heatmapData, topIPs: topIPsChart, complianceTimeline, pieData, logTrend, riskRadarData,
        topRiskyAssets: top5RiskyAssets, 
        allRiskyAssets: allRiskyAssets, // EXPOSED FOR REPORTING
        ipsNeedingAction: ipsNeedingAction, // NEW KPI
        triageData, // NEW CHART DATA
        // ENHANCEMENT: Add simulated geolocation data
        geoLocations: top5RiskyAssets.map(i => { // Only top 5 IPs used for map visualization efficiency
            const geo = getSimulatedGeolocation(i.ip);
            const parts = i.ip.split('.').map(p => parseInt(p, 10));
            return { 
                ip: i.ip, 
                score: i.score, 
                // Generate more varied coordinates for better visual distribution
                x: (parts[2] % 80) + 10, 
                y: (parts[3] % 60) + 20, 
                country: geo.country,
                city: geo.city,
            }
        }),
        fpr: 2.4,
        gdpr: gdprCount,
        owasp: owaspCount,
        threatsByType: typeCount,
    };
};

const generateAIAnalysis = (logs) => {
    const totalLogs = logs.length;
    const critical = logs.filter(l => l.severity === 'Critical').length;
    const high = logs.filter(l => l.severity === 'High').length;
    const medium = logs.filter(l => l.severity === 'Medium').length;
    
    const threats = logs.reduce((acc, l) => {
        if(l.type !== 'Clean') acc[l.type] = (acc[l.type] || 0) + 1;
        return acc;
    }, {});
    const dominantThreat = Object.keys(threats).sort((a,b) => threats[b] - threats[a])[0] || "None";

    const compliance = {
        gdpr: logs.filter(l => l.compliance.includes('GDPR')).length,
        pci: logs.filter(l => l.compliance.includes('PCI-DSS')).length,
        owasp: logs.filter(l => l.compliance.includes('OWASP Top 10')).length
    };

    let narrative = `The current security posture indicates a ${critical > 0 ? 'CRITICAL' : 'STABLE'} status based on ${totalLogs} analyzed events. `;
    if (critical > 0) narrative += `Immediate attention is required for ${critical} critical incidents, primarily driven by ${dominantThreat}. `;
    else narrative += `No critical breaches detected, though ${medium} medium-severity events suggest potential misconfigurations. `;
    
    if (compliance.pci > 0) narrative += `PCI-DSS compliance is compromised (${compliance.pci} violations), indicating potential financial data leakage. `;
    if (compliance.gdpr > 0) narrative += `GDPR exposure detected (${compliance.gdpr} events), risking PII regulatory penalties. `;

    let forecastText = "Based on current velocity, threat volume is stable.";
    if (critical > 5) forecastText = "Threat velocity is accelerating. Expect a 15% increase in brute force attempts over the next 48 hours unless IP blocking is enforced.";
    
    const steps = [];
    if (critical > 0) steps.push("Initiate Incident Response Protocol Alpha for Critical IP containment.");
    if (threats['SQL Injection']) steps.push("Audit WAF rules for SQLi patterns and sanitize database inputs.");
    if (threats['XSS']) steps.push("Review Content Security Policy (CSP) headers on public-facing apps.");
    if (compliance.pci > 0) steps.push("Isolate payment gateway logs and scrub credit card patterns immediately.");
    if (steps.length === 0) steps.push("Maintain standard monitoring. Review False Positive rules to optimize engine noise.");

    return {
        summary: narrative,
        threats,
        compliance,
        forecast: forecastText,
        actionableSteps: steps,
        dominantThreat
    };
};

const LOG_STATUSES = {
    'New': 'New',
    'Investigating': 'Investigating',
    'Closed - Fixed': 'Closed - Fixed',
    'Closed - Benign': 'Closed - Benign',
    'Blocked': 'Blocked', // Existing status
};

// --- MAIN APPLICATION ---
export default function App() {
    const [user, setUser] = useState(null);
    const [userProfile, setUserProfile] = useState(null);
    const [view, setView] = useState('login'); 
    const [logs, setLogs] = useState([]); // All logs (metadata) loaded from Firestore
    const [rules, setRules] = useState([]);
    // activeConnection now includes Firestore data for persistence
    const [activeConnection, setActiveConnection] = useState(null); 
    const [loading, setLoading] = useState(true);

    // PERSISTENCE IMPLEMENTATION: 
    
    // 1. Function to handle updating log status in Firestore
    const handleTriageLog = async (logId, newStatus) => {
        if (!user) return;

        try {
            const logRef = doc(getUserLogsCollectionRef(user.uid), logId);
            await updateDoc(logRef, { status: newStatus, lastUpdated: serverTimestamp() });
        } catch (e) {
            console.error("Error updating log status:", e);
        }
    };
    
    // 2. LIVE POLLING ENGINE (OPTIMIZED) - Logic updated to use Firestore state for 'logs'
    useEffect(() => {
        let interval;
        if (activeConnection && user) {
            console.log(`📡 Starting live stream for ${activeConnection.type}:${activeConnection.host}`);
            interval = setInterval(async () => {
                const retryCount = 0;
                let delay = 1000;
                
                for(let i = 0; i < 3; i++) { 
                    try {
                        // We use the timestamp of the last loaded log to ensure we only pull newer data from the API
                        const lastLog = logs.length > 0 ? logs[logs.length - 1] : null;
                        const lastTimestamp = lastLog ? lastLog.timestamp : null;

                        const response = await fetch(`${API_BASE_URL}/api/connect-db`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ...activeConnection, last_timestamp: lastTimestamp })
                        });
                        
                        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

                        const data = await response.json();
                        
                        if (data.success && data.logs.length > 0) {
                            console.log(`🔥 Frontend received ${data.logs.length} new logs from stream, writing to Firestore.`);
                            const batch = writeBatch(db);

                            data.logs.forEach(logLine => {
                                // IMPORTANT: Analyze the raw log here, but only write the full data once.
                                const newLogData = analyzeLogLine(logLine.raw, logLine.source, logLine.timestamp);
                                const newLogRef = doc(getUserLogsCollectionRef(user.uid)); 
                                batch.set(newLogRef, {
                                    ...newLogData,
                                    createdAt: serverTimestamp() 
                                });
                            });

                            await batch.commit();
                        }
                        break; 
                    } catch (err) {
                        await new Promise(resolve => setTimeout(resolve, delay));
                        delay *= 2; 
                    }
                }
            }, 4000); 
        }
        return () => {
            console.log('🛑 Live stream interval cleared.');
            clearInterval(interval);
        }
    }, [activeConnection, logs, user]); 

    // 3. Firestore Subscription for Logs (CRITICAL PERFORMANCE FIX: Load ALL data, but do NOT limit)
    useEffect(() => {
        if (!user) {
            setLogs([]);
            return;
        }
        // Load ALL logs, ordered by timestamp. This is safe as long as the raw log strings are not huge, 
        // and rendering is limited (which it is, by DISPLAY_LOGS_LIMIT).
        const q = query(
            getUserLogsCollectionRef(user.uid), 
            orderBy('timestamp', 'asc') // Use asc order so analytics calc starts from oldest data
        ); 
        
        const unsubscribe = onSnapshot(q, (snapshot) => {
            console.log(`Loaded ${snapshot.size} logs for analysis.`);
            const fetchedLogs = snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));
            // Now fetchedLogs contains ALL logs, allowing for accurate analytics calculations.
            setLogs(fetchedLogs); 
        }, (error) => {
            console.error("Failed to subscribe to user logs:", error);
        });
        
        return () => unsubscribe();
    }, [user]);

    // 4. Authentication and Config Loading (Mostly unchanged)
    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
            setUser(currentUser);
            if (currentUser) {
                const profileDoc = await getDoc(doc(db, 'artifacts', appId, 'users', currentUser.uid, 'profile', 'data'));
                if (profileDoc.exists()) setUserProfile(profileDoc.data());
                
                const connectionDoc = await getDoc(getConnectionRef(currentUser.uid));
                if (connectionDoc.exists() && connectionDoc.data().isActive) {
                    setActiveConnection(connectionDoc.data());
                }

                setView('dashboard');
            } else {
                setView('login');
                setActiveConnection(null);
            }
            setLoading(false);
        });
        return () => unsubscribe();
    }, []);

    // 5. Rule Subscription (Unchanged)
    useEffect(() => {
        if (!user) return;
        const qRules = query(getUserRulesCollectionRef(user.uid));
        const unsubRules = onSnapshot(qRules, (snap) => {
            setRules(snap.docs.map(d => ({ id: d.id, ...d.data() })));
        }, (err) => console.error("Rule sync error", err));
        return () => unsubRules();
    }, [user]);
    
    // Log Management Handlers
    const handleConnectionEstablished = async (initialLogs, connectionConfig) => {
        setActiveConnection(connectionConfig);
        
        // Batch initial load logs to Firestore
        if (user) {
            const batch = writeBatch(db);
            // DO NOT LIMIT initial load, write all to enable full history.
            initialLogs.forEach(logLine => {
                const newLogData = analyzeLogLine(logLine.raw, logLine.source, logLine.timestamp);
                const newLogRef = doc(getUserLogsCollectionRef(user.uid)); 
                batch.set(newLogRef, {
                    ...newLogData,
                    createdAt: serverTimestamp() 
                });
            });
            await batch.commit();

            await setDoc(getConnectionRef(user.uid), {
                ...connectionConfig,
                isActive: true, 
                lastConnected: serverTimestamp()
            });
        }
    };
    
    const handleDisconnect = async () => {
        setActiveConnection(null);
        // Do NOT clear logs locally, let Firestore handle the state via the listener.
        if (user) {
            await deleteDoc(getConnectionRef(user.uid)).catch(e => console.error("Failed to delete connection config:", e));
        }
    };

    const handleIngest = async (text, source) => {
        if (!user) return;
        const lines = text.split(/\r?\n/).filter(line => line.trim());
        const batch = writeBatch(db);
        
        lines.forEach(line => {
            const newLogData = analyzeLogLine(line, source);
            const newLogRef = doc(getUserLogsCollectionRef(user.uid)); 
            batch.set(newLogRef, {
                ...newLogData,
                createdAt: serverTimestamp() 
            });
        });
        
        try {
            await batch.commit();
        } catch (e) {
            console.error("Error batching logs:", e);
        }
    };

    const handleLogout = async () => { 
        await signOut(auth); 
        setUserProfile(null); 
        handleDisconnect(); 
    };

    if (loading) return <div className="h-screen w-full bg-slate-950 flex items-center justify-center text-cyan-500 font-mono">INITIALIZING...</div>;

    return (
        <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30">
            <div className="fixed inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>
            {!user ? <AuthScreen /> : (
                <div className="relative z-10 flex h-screen overflow-hidden">
                    <Sidebar view={view} setView={setView} onLogout={handleLogout} />
                    <main className="flex-1 overflow-y-auto p-6">
                        <Header userProfile={userProfile} user={user} activeConnection={activeConnection} />
                        {view === 'dashboard' && <Dashboard logs={logs} user={user} handleTriageLog={handleTriageLog} />}
                        {view === 'ingest' && <IngestCenter onIngest={handleIngest} />}
                        {view === 'terminal' && <LiveTerminal logs={logs} onIngest={handleIngest} />}
                        {view === 'automation' && <AutomationCenter rules={rules} userId={user.uid} />}
                        {view === 'reports' && <ReportCenter logs={logs} userProfile={userProfile} />}
                        {view === 'connectors' && <DBConnectors onConnectionEstablished={handleConnectionEstablished} onDisconnect={handleDisconnect} activeConnection={activeConnection} userId={user.uid} />}
                        {view === 'copilot' && <AICopilot logs={logs} />}
                    </main>
                </div>
            )}
        </div>
    );
}

// --- SUB COMPONENTS ---

const Card = ({ children, className = "" }) => (
    <div className={`bg-slate-900/50 backdrop-blur-md border border-slate-700/50 p-6 rounded-xl shadow-xl ${className}`}>
        {children}
    </div>
);

const Badge = ({ severity }) => {
    const colors = {
        Critical: 'bg-red-500/20 text-red-400 border-red-500/50',
        High: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
        Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
        Low: 'bg-green-500/20 text-green-400 border-green-500/50',
        Clean: 'bg-blue-500/20 text-blue-400 border-blue-500/50'
    };
    return (
        <span className={`px-2 py-1 rounded text-xs border font-medium ${colors[severity] || colors.Clean}`}>
            {severity}
        </span>
    );
};

// ENHANCED WorldMap Component
const WorldMap = ({ locations }) => {
    // CSS Keyframes for a subtle "breathing" effect on the globe and hotspots
    const styleSheet = `
        @keyframes pulse-hotspot {
            0% { box-shadow: 0 0 5px 0px rgba(239, 68, 68, 0.8); }
            50% { box-shadow: 0 0 15px 3px rgba(239, 68, 68, 0.4); }
            100% { box-shadow: 0 0 5px 0px rgba(239, 68, 68, 0.8); }
        }
        .hotspot { animation: pulse-hotspot 2s infinite ease-in-out; }
    `;

    return (
        <div className="relative w-full h-full min-h-[300px] bg-slate-900/50 rounded-lg overflow-hidden flex items-center justify-center">
            {/* Inject dynamic CSS */}
            <style>{styleSheet}</style>

            {/* Stylized SVG Globe background */}
            <svg viewBox="0 0 800 400" className="w-full h-full opacity-50">
                <rect width="800" height="400" fill="#0f172a" />
                <defs>
                    {/* Ocean texture */}
                    <filter id="glow"><feGaussianBlur stdDeviation="3" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                    
                    {/* Landmass (stylized, fictional geography) */}
                    <path id="land" fill="#334155" d="M150,120 Q180,60 250,80 T350,100 T450,90 T550,80 T650,100 Q750,120 700,200 T550,300 T400,320 T250,300 T100,250 Z M50,100 Q80,80 100,120 T80,180 Z M600,150 Q650,180 700,150 T750,100 T700,50 Z M500,250 Q450,220 400,250 T350,280 T300,250 Z" />
                    
                    {/* Grid/Lines for scanning effect */}
                    <pattern id="scanlines" width="40" height="40" patternUnits="userSpaceOnUse">
                        <path d="M 0 10 L 40 10 M 0 30 L 40 30" stroke="#1e293b" strokeWidth="0.5" />
                    </pattern>
                </defs>
                
                {/* Apply scanning pattern */}
                <rect width="100%" height="100%" fill="url(#scanlines)" />
                
                {/* Apply glow to landmass */}
                <use href="#land" filter="url(#glow)" className="opacity-70"/>
                <use href="#land" className="opacity-80"/>
            </svg>
            
            {/* Live Hotspots (Threat Origins) */}
            {locations.map((loc, i) => (
                <div 
                    key={i} 
                    className="absolute w-3 h-3 bg-red-500 rounded-full shadow-[0_0_10px_rgba(239,68,68,0.8)] hotspot cursor-help" 
                    style={{ top: `${loc.y}%`, left: `${loc.x}%` }} 
                    // Tooltip now shows simulated geolocation (IP, City, and Country)
                    title={`IP: ${loc.ip} | Location: ${loc.city}, ${loc.country} | Score: ${loc.score}`}
                ></div>
            ))}
            
            <div className="absolute bottom-4 left-4 text-xs text-slate-500 bg-slate-900/80 px-2 py-1 rounded border border-slate-700">Live Threat Origins (Simulated Geo-View)</div>
            
        </div>
    );
};

// Updated Header to display user name and role
const Header = ({ userProfile, user, activeConnection }) => (
    <header className="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
        <div>
            <h1 className="text-2xl font-bold text-white tracking-wider flex items-center gap-2">
                <Shield className="w-6 h-6 text-cyan-400" /> Sentinel <span className="text-cyan-500 text-sm bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800">PRO v2.4</span>
            </h1>
            <p className="text-slate-400 text-xs font-mono mt-1 flex items-center gap-2">
                {activeConnection ? <span className="text-emerald-400 animate-pulse flex items-center gap-1">● LIVE STREAMING: {activeConnection.type.toUpperCase()} @ {activeConnection.host}</span> : 'OFFLINE MODE'} 
                :: {userProfile?.company || 'ORG'}
            </p>
        </div>
        
        {/* User Account Section */}
        <div className="flex items-center gap-4">
            <div className="text-right hidden md:block">
                <div className="font-bold text-sm text-white">{userProfile?.fullName || user?.email || 'Sentinel Agent'}</div>
                <div className="text-xs text-slate-400">{userProfile?.role || 'Security Analyst'}</div>
            </div>
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center border-2 border-slate-900 shadow-lg">
                {userProfile?.fullName ? 
                    <span className="text-white font-bold text-lg">{userProfile.fullName[0].toUpperCase()}</span> : 
                    <User className="w-5 h-5 text-white" />
                }
            </div>
        </div>
    </header>
);

const AuthScreen = () => {
    const [authMode, setAuthMode] = useState('login'); 
    const [formData, setFormData] = useState({ email: '', password: '', fullName: '', company: '', role: '', industry: 'Technology' });
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');
    const handleChange = (e) => setFormData({...formData, [e.target.name]: e.target.value});
    const handleSubmit = async (e) => {
        e.preventDefault(); setError(''); setMessage('');
        try {
            if (authMode === 'login') await signInWithEmailAndPassword(auth, formData.email, formData.password);
            else if (authMode === 'register') {
                const userCredential = await createUserWithEmailAndPassword(auth, formData.email, formData.password);
                await setDoc(doc(db, 'artifacts', appId, 'users', userCredential.user.uid, 'profile', 'data'), {
                    fullName: formData.fullName, company: formData.company, role: formData.role, industry: formData.industry, email: formData.email, createdAt: serverTimestamp()
                });
                await updateProfile(userCredential.user, { displayName: formData.fullName });
            } else if (authMode === 'forgot') {
                await sendPasswordResetEmail(auth, formData.email); setMessage('Password reset link sent.');
            }
        } catch (err) { setError(err.message.replace('Firebase: ', '')); }
    };
    return (
        <div className="h-screen w-full flex items-center justify-center relative z-20 px-4">
            <Card className="w-full max-w-md border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.15)] bg-slate-950/80">
                <div className="text-center mb-6">
                    <Shield className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
                    <h2 className="text-3xl font-bold text-white mb-2">Sentinel Platform</h2>
                    <p className="text-slate-400 text-sm">{authMode === 'login' ? 'Secure Identity Verification' : 'Agent Onboarding'}</p>
                </div>
                {error && <div className="bg-red-500/20 border border-red-500/50 text-red-300 p-3 rounded mb-4 text-xs font-mono">{error}</div>}
                {message && <div className="bg-green-500/20 border border-green-500/50 text-green-300 p-3 rounded mb-4 text-xs font-mono">{message}</div>}
                <form onSubmit={handleSubmit} className="space-y-4">
                    {authMode !== 'forgot' && <input type="password" name="password" required placeholder="Password" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white w-full" onChange={handleChange} />}
                    <button className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2 rounded uppercase text-sm">Submit</button>
                </form>
                <div className="mt-4 flex justify-between text-xs text-slate-500">
                    <button onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}>{authMode === 'login' ? 'Create Account' : 'Login'}</button>
                    {authMode === 'login' && <button onClick={() => setAuthMode('forgot')}>Forgot?</button>}
                </div>
            </Card>
        </div>
    );
};

const Sidebar = ({ view, setView, onLogout }) => {
    const menu = [
        { id: 'dashboard', icon: Activity, label: 'Overview' },
        { id: 'ingest', icon: FileText, label: 'Log Ingestion' },
        { id: 'connectors', icon: Database, label: 'DB Connectors' },
        { id: 'terminal', icon: Terminal, label: 'Live Terminal' },
        { id: 'automation', icon: Zap, label: 'Automation' },
        { id: 'reports', icon: Download, label: 'Reports & Export' },
        { id: 'copilot', icon: Lightbulb, label: 'AI Copilot' },
    ];
    return (
        <aside className="w-20 md:w-64 flex-shrink-0 border-r border-slate-800 bg-slate-900/30 flex flex-col justify-between backdrop-blur-sm">
            <div className="p-4 space-y-2">
                {menu.map(item => (
                    <button key={item.id} onClick={() => setView(item.id)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${view === item.id ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}>
                        <item.icon className="w-5 h-5" /><span className="hidden md:block font-medium text-sm">{item.label}</span>
                    </button>
                ))}
            </div>
            <div className="p-4 border-t border-slate-800">
                <button onClick={onLogout} className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors"><Lock className="w-5 h-5" /><span className="hidden md:block font-medium text-sm">Terminate Session</span></button>
            </div>
        </aside>
    );
};

// DBConnectors updated for disconnect and generalized types
const DBConnectors = ({ onConnectionEstablished, onDisconnect, activeConnection }) => {
    // Set host to localhost and DB port default to 3306 for simulation, making them read-only.
    const defaultForm = { type: 'mysql', host: 'localhost', port: '3306', user: 'root', password: '', database: 'sentinel_logs' };
    const [formData, setFormData] = useState(defaultForm);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        // Pre-fill form if a connection is active
        if (activeConnection) {
            setFormData(activeConnection);
        } else {
            setFormData(defaultForm);
        }
    }, [activeConnection]);

    // Helper to update port based on selected DB type for better UX
    const handleTypeChange = (e) => {
        const type = e.target.value;
        let port = '3306'; // Default MySQL
        if (type === 'postgresql') port = '5432';
        if (type === 'mongodb') port = '27017';
        setFormData(prev => ({...prev, type, port}));
    }

    const handleConnect = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE_URL}/api/connect-db`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(formData)
            });
            const data = await response.json();
            
            if (data.success) {
                if (onConnectionEstablished) {
                    onConnectionEstablished(data.logs, formData);
                }
                // Using a custom UI element instead of alert() for user feedback
                console.log(`Connected to ${formData.type}! Fetched ${data.logs.length} logs. Live streaming active.`); 
            } else {
                console.error(`Connection Failed: ${data.message}`);
                // In a real app, show an error modal here
            }
        } catch (err) { 
            console.error("API Error: Backend simulation service unreachable:", err); 
        } 
        finally { setLoading(false); }
    };

    if (activeConnection) {
        return (
            <div className="max-w-2xl mx-auto">
                <Card className="border-red-500/30">
                    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                        <Database className="w-6 h-6 text-emerald-400 animate-pulse"/> 
                        Live Stream Active
                    </h2>
                    <p className="text-sm text-slate-400 mb-6">
                        Streaming logs from <strong>{activeConnection.type.toUpperCase()}</strong> at 
                        <span className="font-mono text-cyan-400 ml-1">{activeConnection.host}:{activeConnection.port}</span>. 
                        Data is ingested and analyzed in real-time.
                    </p>
                    <button 
                        onClick={onDisconnect} 
                        className="w-full bg-red-600 hover:bg-red-500 text-white font-bold py-2 rounded uppercase text-sm flex items-center justify-center gap-2"
                    >
                        <LogOut className="w-4 h-4"/> Terminate Connection
                    </button>
                </Card>
            </div>
        );
    }

    return (
        <div className="max-w-2xl mx-auto">
            <Card>
                <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2"><Database className="w-5 h-5 text-cyan-400"/> Live Connector Setup</h2>
                <form onSubmit={handleConnect} className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <select className="bg-slate-900 text-white p-2 rounded border border-slate-700" onChange={handleTypeChange} value={formData.type}>
                            <option value="mysql">MySQL</option>
                            <option value="postgresql">PostgreSQL</option>
                            <option value="mongodb">MongoDB</option>
                        </select>
                        {/* Host field: Pre-filled and Read-Only as requested */}
                        <input className="bg-slate-900 text-white p-2 rounded border border-slate-700 read-only:bg-slate-800 read-only:text-slate-500 cursor-not-allowed" placeholder="Host" value={formData.host} readOnly title="Host is fixed for this simulated environment." />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        {/* Port field: Pre-filled and Read-Only */}
                        <input className="bg-slate-900 text-white p-2 rounded border border-slate-700 read-only:bg-slate-800 read-only:text-slate-500 cursor-not-allowed" placeholder="Port" value={formData.port} readOnly title="Port is set by the database type in this simulated environment."/>
                        <input className="bg-slate-900 text-white p-2 rounded border border-slate-700" placeholder="User" value={formData.user} onChange={e => setFormData({...formData, user: e.target.value})} required />
                    </div>
                    <input className="bg-slate-900 text-white p-2 rounded border border-slate-700 w-full" type="password" placeholder="Password" value={formData.password} onChange={e => setFormData({...formData, password: e.target.value})} />
                    <input className="bg-slate-900 text-white p-2 rounded border border-slate-700 w-full" placeholder="Database Name" value={formData.database} onChange={e => setFormData({...formData, database: e.target.value})} required />
                    <button disabled={loading} className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2 rounded flex items-center justify-center gap-2">
                        {loading ? 'Connecting...' : <><Zap className="w-4 h-4"/> Establish Live Stream</>}
                    </button>
                </form>
            </Card>
        </div>
    );
};

// Component for Status Button/Triage Menu
const StatusButton = ({ logId, currentStatus, onTriage }) => {
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const options = Object.keys(LOG_STATUSES).filter(s => s !== currentStatus);
    
    const statusColors = {
        'New': 'text-blue-400 border-blue-500/30 bg-blue-500/10', 
        'Investigating': 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10', 
        'Closed - Fixed': 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
        'Closed - Benign': 'text-green-400 border-green-500/30 bg-green-500/10',
        'Blocked': 'text-red-400 border-red-500/30 bg-red-500/10'
    };

    return (
        <div className="relative inline-block">
            <button 
                onClick={() => setIsMenuOpen(!isMenuOpen)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${statusColors[currentStatus] || statusColors['New']} flex items-center gap-1 min-w-[100px] justify-between`}
            >
                {currentStatus}
                <Layers className="w-3 h-3"/>
            </button>
            {isMenuOpen && (
                <div className="absolute z-50 w-48 mt-1 bg-slate-900 border border-slate-700 rounded-lg shadow-lg right-0">
                    {options.map(status => (
                        <button
                            key={status}
                            className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
                            onClick={() => { onTriage(logId, status); setIsMenuOpen(false); }}
                        >
                            Set to {LOG_STATUSES[status]}
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
};

const Dashboard = ({ logs, user, handleTriageLog }) => {
    // New State for Display Toggle and Date Filtering
    const [showAllLogs, setShowAllLogs] = useState(false); 
    const [logStatusFilter, setLogStatusFilter] = useState('New'); 
    const [searchTerm, setSearchTerm] = useState('');
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');

    const filteredLogs = useMemo(() => {
        let filtered = logs;
        
        // --- 1. Date Range Filter ---
        if (startDate || endDate) {
            const startTimestamp = startDate ? new Date(startDate).getTime() : 0;
            const endTimestamp = endDate ? new Date(endDate).getTime() : Infinity;

            if (!isNaN(startTimestamp) && !isNaN(endTimestamp)) {
                 filtered = filtered.filter(log => {
                    const logTime = new Date(log.timestamp).getTime();
                    return logTime >= startTimestamp && logTime <= endTimestamp;
                });
            }
        }

        // --- 2. Status Filter ---
        if (logStatusFilter !== 'All') {
            filtered = filtered.filter(log => log.status === logStatusFilter);
        }

        // --- 3. Search Filter ---
        if (searchTerm) {
            const lowerCaseSearch = searchTerm.toLowerCase();
            filtered = filtered.filter(log => 
                log.raw?.toLowerCase().includes(lowerCaseSearch) || 
                log.type.toLowerCase().includes(lowerCaseSearch) ||
                log.ip.includes(lowerCaseSearch)
            );
        }

        // 4. Performance/Display Toggle: Only apply limit if showAllLogs is false
        const finalLogs = filtered.slice().reverse(); // Sort descending (latest first)
        
        if (!showAllLogs && finalLogs.length > DISPLAY_LOGS_LIMIT) {
             return finalLogs.slice(0, DISPLAY_LOGS_LIMIT);
        }

        return finalLogs;

    }, [logs, logStatusFilter, searchTerm, showAllLogs, startDate, endDate]);

    // Recalculate stats based on ALL logs (not filtered logs)
    const stats = useMemo(() => calculateAnalytics(logs), [logs]);
    const COLORS = ['#06b6d4', '#ef4444', '#f59e0b', '#10b981', '#6366f1'];
    const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    
    // Triage Chart Color mapping
    const triageBarColors = {
        'New': '#0ea5e9',
        'Investigating': '#eab308',
        'Blocked': '#ef4444',
        'Closed - Fixed': '#10b981',
        'Closed - Benign': '#34d399',
    };

    const handleFalsePositive = async (logId) => {
        if (!user) return;
        handleTriageLog(logId, 'Closed - Benign');
    };

    const handleBlockIP = async (log) => {
        if (!user) return;
        
        handleTriageLog(log.id, 'Blocked'); 
        
        try {
            await addDoc(getUserRulesCollectionRef(user.uid), { name: `Manual Block ${log.ip}`, conditionField: 'ip', conditionValue: log.ip, action: 'BLOCK_IP' });
            const response = await fetch(`${API_BASE_URL}/api/block-ip`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: log.ip })
            });
            const result = await response.json();
            if(result.success) console.log(`IP ${log.ip} blocked successfully via Backend`);
        } catch (e) {
            console.error("Error blocking IP or reaching backend:", e);
        }
    };
    
    // Re-calculating status counts for the filter badges
    const statusCounts = useMemo(() => {
        return logs.reduce((acc, log) => {
            acc[log.status] = (acc[log.status] || 0) + 1;
            return acc;
        }, { 'All': logs.length });
    }, [logs]);


    return (
        <div className="space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
                <Card className="border-t-4 border-t-cyan-500"><div className="text-slate-400 text-xs uppercase tracking-widest font-bold mb-2">Total Analyzed</div><div className="text-3xl font-mono text-white">{stats.total}</div></Card>
                <Card className="border-t-4 border-t-purple-500"><div className="text-purple-400 text-xs uppercase tracking-widest font-bold mb-2">Risk Velocity</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.velocity > 0 ? '+' : ''}{stats.velocity.toFixed(0)}%</div>{stats.velocity > 0 ? <TrendingUp className="w-6 h-6 text-red-500 mb-1" /> : <TrendingDown className="w-6 h-6 text-green-500 mb-1" />}</div></Card>
                <Card className="border-t-4 border-t-pink-500"><div className="text-pink-400 text-xs uppercase tracking-widest font-bold mb-2">MTTD</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.mttdMinutes}<span className="text-sm text-slate-500 ml-1">min</span></div><Clock className="w-6 h-6 text-pink-500 mb-1" /></div></Card>
                <Card className="border-t-4 border-t-emerald-500"><div className="text-emerald-400 text-xs uppercase tracking-widest font-bold mb-2">Compliance</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.complianceScore}%</div><CheckSquare className="w-6 h-6 text-emerald-500 mb-1" /></div></Card>
                <Card className="border-t-4 border-t-red-500"><div className="text-red-400 text-xs uppercase tracking-widest font-bold mb-2">Risky IPs Action</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.ipsNeedingAction}</div><AlertTriangle className="w-6 h-6 text-red-500 mb-1" /></div></Card>
            </div>

            {/* Visualizations - Row 1 */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <Card className="lg:col-span-1"><h3 className="text-white font-bold mb-4 flex items-center gap-2"><Server className="w-4 h-4 text-red-400"/> Risky Assets (Top 5)</h3><div className="space-y-3">{stats.topRiskyAssets.length > 0 ? stats.topRiskyAssets.map(asset => (<div key={asset.ip} className="flex items-center justify-between p-2 bg-slate-800/50 rounded border border-slate-700"><div><div className="font-mono text-sm text-white">{asset.ip}</div><div className="text-[10px] text-slate-500 flex gap-2"><span className="text-red-400">{asset.critical} Crit</span><span className="text-orange-400">{asset.high} High</span></div></div><div className="text-right"><div className="text-xl font-bold text-red-500">{asset.score}</div><div className="text-[10px] uppercase text-slate-600">Risk Score</div></div></div>)) : <div className="text-slate-500 text-sm italic">No risky assets detected.</div>}</div></Card>
                <Card className="lg:col-span-2 h-[400px]"><h3 className="text-white font-bold mb-4 flex items-center gap-2"><Map className="w-4 h-4 text-cyan-400"/> Global Threat Origins (Simulated)</h3><WorldMap locations={stats.geoLocations} /></Card>
            </div>

            {/* Visualizations - Row 2 (Charts) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                 {/* New Triage Status Bar Chart */}
                <Card className="lg:col-span-1 h-80">
                    <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Briefcase className="w-4 h-4 text-emerald-400"/> Current Triage Workload</h3>
                    
                    <ResponsiveContainer width="100%" height="90%">
                        <BarChart data={stats.triageData} margin={{ top: 5, right: 0, left: -20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                            <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 10 }} angle={-30} textAnchor="end" height={40} />
                            <YAxis stroke="#94a3b8" />
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} itemStyle={{ color: '#fff' }} />
                            <Bar dataKey="count" name="Alert Count" radius={[4, 4, 0, 0]}>
                                {stats.triageData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={triageBarColors[entry.name] || '#64748b'} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </Card>

                {/* Compliance/Ingestion Trends */}
                <Card className="lg:col-span-2 h-80">
                    <h3 className="text-white font-bold mb-4 flex items-center gap-2"><BarChart3 className="w-4 h-4 text-purple-400"/> Log & Compliance Trends</h3>
                    
                    <ResponsiveContainer width="100%" height="90%">
                        <LineChart data={stats.logTrend} margin={{ top: 5, right: 20, left: -20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="date" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                            <YAxis yAxisId="left" stroke="#94a3b8" />
                            <YAxis yAxisId="right" orientation="right" stroke="#f97316" />
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} itemStyle={{ color: '#fff' }} />
                            <Legend />
                            <Line yAxisId="left" type="monotone" dataKey="total" name="Total Logs Ingested" stroke="#a78bfa" strokeWidth={2} dot={false} />
                            <Line yAxisId="right" type="monotone" dataKey="gdpr" name="GDPR Violations" stroke="#06b6d4" strokeWidth={1} dot={false} strokeDasharray="5 5" />
                            <Line yAxisId="right" type="monotone" dataKey="pci" name="PCI Violations" stroke="#f97316" strokeWidth={1} dot={false} strokeDasharray="3 3" />
                        </LineChart>
                    </ResponsiveContainer>
                </Card>
            </div>
            
            {/* Visualizations - Row 3 (Distribution) */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card className="h-80">
                    <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400"/> Threat Distribution</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie data={stats.pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                                {stats.pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="rgba(0,0,0,0.5)" />)}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} itemStyle={{ color: '#fff' }} />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                </Card>
                <Card className="h-80">
                    <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Globe className="w-4 h-4 text-cyan-400"/> Risk Radar</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <RadarChart outerRadius={90} data={stats.riskRadarData}>
                            <PolarGrid stroke="#334155" />
                            <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                            <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#334155"/>
                            <Radar name="Threat Level" dataKey="A" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.3} />
                        </RadarChart>
                    </ResponsiveContainer>
                </Card>
            </div>


            <Card>
                <h3 className="text-white font-bold mb-4">Recent Alerts & Remediation</h3>
                
                {/* Triage/Filter/Search Bar */}
                <div className="flex flex-col md:flex-row justify-between items-center mb-4 gap-3">
                    {/* Status Filters */}
                    <div className="flex space-x-2 overflow-x-auto pb-1">
                        {Object.keys(LOG_STATUSES).concat(['All']).map(status => (
                            <button 
                                key={status} 
                                onClick={() => setLogStatusFilter(status)}
                                className={`px-3 py-1 text-xs rounded-full font-medium transition-all border ${
                                    logStatusFilter === status 
                                        ? 'bg-cyan-600 text-white border-cyan-500' 
                                        : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                                }`}
                            >
                                {status} ({statusCounts[status] || 0})
                            </button>
                        ))}
                    </div>
                    
                    {/* Date Filters */}
                    <div className="flex gap-2 w-full md:w-auto">
                        <input 
                            type="date"
                            placeholder="Start Date"
                            value={startDate}
                            onChange={(e) => setStartDate(e.target.value)}
                            className="bg-slate-900 border border-slate-700 rounded-lg py-2 px-3 text-sm text-white focus:ring-cyan-500 focus:border-cyan-500 w-full"
                        />
                         <input 
                            type="date"
                            placeholder="End Date"
                            value={endDate}
                            onChange={(e) => setEndDate(e.target.value)}
                            className="bg-slate-900 border border-slate-700 rounded-lg py-2 px-3 text-sm text-white focus:ring-cyan-500 focus:border-cyan-500 w-full"
                        />
                    </div>
                    
                    {/* Search Bar */}
                    <div className="relative w-full md:w-64">
                        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 transform -translate-y-1/2" />
                        <input 
                            type="text"
                            placeholder="Search raw logs..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full bg-slate-900 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-sm text-white focus:ring-cyan-500 focus:border-cyan-500"
                        />
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <p className={`text-xs mb-2 p-2 rounded flex items-center justify-between ${showAllLogs ? 'bg-red-900/10 border border-red-500/30 text-red-400' : 'bg-yellow-900/10 border border-yellow-500/30 text-yellow-400'}`}>
                        <span>
                            Analyzing **{logs.length}** total logs in database. 
                            Displaying **{filteredLogs.length}** {showAllLogs ? ' filtered records (Caution: Performance risk).' : ` most recent filtered records for stability.`}
                        </span>
                        {/* The logic below handles the performance toggle */}
                        {(logs.length > DISPLAY_LOGS_LIMIT || filteredLogs.length > DISPLAY_LOGS_LIMIT) && (
                            <button 
                                onClick={() => setShowAllLogs(!showAllLogs)}
                                className={`ml-4 text-xs font-bold px-2 py-0.5 rounded transition-colors ${showAllLogs ? 'bg-red-500 hover:bg-red-600 text-white' : 'bg-yellow-600 hover:bg-yellow-700 text-white'}`}
                            >
                                {showAllLogs ? 'Re-limit View' : `View All (${filteredLogs.length} Records)`}
                            </button>
                        )}
                    </p>
                    <table className="w-full text-sm text-left text-slate-400">
                        <thead className="text-xs text-slate-500 uppercase bg-slate-800/50">
                            <tr>
                                <th className="px-4 py-3">Timestamp</th>
                                <th className="px-4 py-3">Severity</th>
                                <th className="px-4 py-3">Type</th>
                                <th className="px-4 py-3">Source IP</th>
                                <th className="px-4 py-3">Status / Triage</th>
                                <th className="px-4 py-3">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {/* filteredLogs is already reversed (latest first) and limited by useMemo */}
                            {filteredLogs.map(log => ( 
                                <tr key={log.id} className={`border-b border-slate-800 hover:bg-slate-800/30 ${log.status === 'Blocked' ? 'opacity-50' : ''}`}>
                                    <td className="px-4 py-3 font-mono text-xs">{new Date(log.timestamp).toLocaleTimeString()}</td>
                                    <td className="px-4 py-3"><Badge severity={log.severity} /></td>
                                    <td className="px-4 py-3 text-white">{log.type}</td>
                                    <td className="px-4 py-3 font-mono text-xs">{log.ip}</td>
                                    <td className="px-4 py-3">
                                        <StatusButton 
                                            logId={log.id} 
                                            currentStatus={log.status} 
                                            onTriage={handleTriageLog}
                                        />
                                    </td>
                                    <td className="px-4 py-3 flex gap-2">
                                        <button onClick={() => handleBlockIP(log)} title="Block IP" className="p-1 rounded hover:bg-red-500/20 text-slate-400 hover:text-red-400"><Ban className="w-4 h-4" /></button>
                                        <button onClick={() => handleFalsePositive(log.id)} title="Mark Benign" className="p-1 rounded hover:bg-green-500/20 text-slate-400 hover:text-green-400"><ThumbsUp className="w-4 h-4" /></button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

const ReportCenter = ({ logs, userProfile }) => {
    const stats = useMemo(() => calculateAnalytics(logs), [logs]);
    const aiAnalysis = useMemo(() => generateAIAnalysis(logs), [logs]);

    // NEW: Function to handle Excel-compatible TSV export (using .csv extension for better compatibility)
    const handleExcelExport = () => {
        const separator = '\t'; // Tab separator for Excel compatibility
        
        // Define column headers
        const headers = ["ID", "Timestamp", "Severity", "Threat Type", "IP Address", "Compliance Tags", "Raw Log", "Status"];
        
        // Map log data to TSV rows
        const tsvRows = logs.map(log => {
            // Escape double quotes and remove newlines from raw log data
            const sanitizedRawLog = log.raw
                .replace(/"/g, '""')
                .replace(/\n/g, ' ')
                .replace(/\r/g, ''); 
            
            return [
                log.id,
                new Date(log.timestamp).toISOString(),
                log.severity,
                log.type,
                log.ip,
                log.compliance.join('; '),
                `"${sanitizedRawLog}"`, // Enclose raw log in quotes
                log.status
            ].join(separator);
        });
        
        // Combine headers and rows
        const tsvContent = [
            headers.join(separator),
            ...tsvRows
        ].join('\n');

        // Use 'text/tsv' MIME type and the .csv extension
        const blob = new Blob([tsvContent], { type: 'text/tsv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        
        link.setAttribute('href', url);
        // Using .csv extension for reliable parsing by Excel, even though the data is TSV
        link.setAttribute('download', `Sentinel_Export_${new Date().toISOString().split('T')[0]}.csv`); 
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    };

    const handlePrint = () => {
        const printWindow = window.open('', '', 'width=1200,height=1200');
        const date = new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        
        // Detailed HTML structure and styles for the report
        const styles = `
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&display=swap');
                body { font-family: 'Inter', sans-serif; padding: 40px; color: #1e293b; line-height: 1.6; max-width: 1000px; margin: 0 auto; background: #fff; }
                .page-header { border-bottom: 4px solid #0f172a; padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: flex-end; }
                .logo { font-size: 32px; font-weight: 800; color: #0f172a; text-transform: uppercase; letter-spacing: -1px; }
                .sub-logo { font-size: 14px; font-weight: 400; color: #64748b; margin-top: 5px; }
                .meta-box { text-align: right; font-size: 12px; color: #64748b; line-height: 1.4; }
                
                h1 { font-size: 26px; font-weight: 800; margin: 40px 0 20px; color: #0f172a; border-left: 6px solid #06b6d4; padding-left: 15px; }
                h2 { font-size: 18px; font-weight: 700; margin: 30px 0 15px; color: #334155; }
                
                .dashboard-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }
                .kpi-card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; text-align: center; }
                .kpi-label { font-size: 11px; text-transform: uppercase; font-weight: 600; color: #64748b; letter-spacing: 0.5px; margin-bottom: 8px; }
                .kpi-value { font-size: 28px; font-weight: 800; color: #0f172a; }
                
                .exec-summary { background: #eff6ff; border: 1px solid #bfdbfe; padding: 25px; border-radius: 8px; font-size: 15px; color: #1e3a8a; margin-bottom: 40px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
                
                table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 30px; border: 1px solid #e2e8f0; }
                th { text-align: left; background: #f1f5f9; padding: 12px 15px; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; }
                td { border-bottom: 1px solid #e2e8f0; padding: 12px 15px; color: #334155; vertical-align: top; }
                tr:last-child td { border-bottom: none; }
                .risk-critical { color: #dc2626; font-weight: 600; background: #fef2f2; padding: 2px 6px; border-radius: 4px; }
                .risk-high { color: #f97316; font-weight: 600; background: #fff7ed; padding: 2px 6px; border-radius: 4px; }
                .risk-med { color: #eab308; font-weight: 600; background: #fffbeb; padding: 2px 6px; border-radius: 4px; }
                .risk-low { color: #10b981; font-weight: 600; background: #ecfdf5; padding: 2px 6px; border-radius: 4px; }
                
                .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; }
                
                ul.remediation-list { list-style: none; padding: 0; }
                ul.remediation-list li { background: #fff; border: 1px solid #e2e8f0; padding: 15px; margin-bottom: 10px; border-radius: 6px; border-left: 4px solid #06b6d4; }
                
                .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; font-size: 11px; color: #94a3b8; }
            </style>
        `;

        const threatTypeRows = Object.entries(stats.threatsByType)
            .sort(([, a], [, b]) => b - a)
            .map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`)
            .join('');

        // Use allRiskyAssets (the full list) and filter only those needing blocking/investigation
        const ipToBlockRows = stats.allRiskyAssets
            .filter(a => a.score >= 5) // Filter IPs with a score of 5 or more (multiple events or critical data)
            .map(a => `
                <tr>
                    <td><strong>${a.ip}</strong></td>
                    <td><span class="${a.score >= 15 ? 'risk-critical' : 'risk-high'}">${a.score}</span></td>
                    <td>${a.critical}</td>
                    <td>${a.high}</td>
                    <td>${a.action}</td>
                </tr>
            `).join('');

        const html = `
            <html>
                <head><title>Sentinel Executive Security Brief</title>${styles}</head>
                <body>
                    <div class="page-header">
                        <div>
                            <div class="logo">Sentinel</div>
                            <div class="sub-logo">Advanced Threat Intelligence Platform</div>
                        </div>
                        <div class="meta-box">
                            <strong>REPORT GENERATED</strong><br>${date}<br>
                            Analyst: ${userProfile?.fullName || 'N/A'}<br><br>
                            <strong>TOTAL LOGS ANALYZED:</strong> ${stats.total}<br>
                            <strong>CLASSIFICATION</strong><br>INTERNAL USE ONLY
                        </div>
                    </div>

                    <h1>1. Executive Strategic Summary</h1>
                    <div class="exec-summary">
                        <strong>Situation Analysis:</strong> ${aiAnalysis.summary}
                        <br><br>
                        <strong>Strategic Forecast:</strong> ${aiAnalysis.forecast}
                    </div>

                    <h1>2. Key Performance Indicators (KPI) Summary</h1>
                    <div class="dashboard-grid">
                        <div class="kpi-card" style="border-top: 4px solid #ef4444;"><div class="kpi-label" style="color:#ef4444;">Critical Events</div><div class="kpi-value">${stats.critical}</div></div>
                        <div class="kpi-card" style="border-top: 4px solid #f97316;"><div class="kpi-label" style="color:#f97316;">High Risk Events</div><div class="kpi-value">${stats.high}</div></div>
                        <div class="kpi-card" style="border-top: 4px solid #eab308;"><div class="kpi-label" style="color:#eab308;">Risky IPs Identified</div><div class="kpi-value">${stats.ipsNeedingAction}</div></div>
                        <div class="kpi-card" style="border-top: 4px solid #10b981;"><div class="kpi-label" style="color:#10b981;">Total Analyzed Logs</div><div class="kpi-value">${stats.total}</div></div>
                    </div>
                    
                    <div class="dashboard-grid" style="grid-template-columns: repeat(3, 1fr);">
                        <div class="kpi-card" style="border-top: 4px solid #06b6d4;"><div class="kpi-label" style="color:#06b6d4;">Compliance Score</div><div class="kpi-value">${stats.complianceScore}%</div></div>
                        <div class="kpi-card" style="border-top: 4px solid #a78bfa;"><div class="kpi-label" style="color:#a78bfa;">Risk Velocity</div><div class="kpi-value" style="color:${stats.velocity > 0 ? '#dc2626' : '#16a34a'}">${stats.velocity > 0 ? '+' : ''}${stats.velocity.toFixed(0)}%</div></div>
                        <div class="kpi-card" style="border-top: 4px solid #ec4899;"><div class="kpi-label" style="color:#ec4899;">MTTD (Avg)</div><div class="kpi-value">${stats.mttdMinutes}m</div></div>
                    </div>


                    <div class="two-col">
                        <div>
                            <h1>3. Threat Landscape Breakdown</h1>
                            <h2>By Attack Vector Type</h2>
                            <table>
                                <tr><th>Attack Vector</th><th>Event Count</th></tr>
                                ${threatTypeRows}
                            </table>
                        </div>
                        <div>
                            <h1>4. Compliance Audit Details</h1>
                            <h2>Violation Summary</h2>
                            <table>
                                <tr><th>Framework</th><th>Violations</th><th>Status</th></tr>
                                <tr><td>GDPR (Privacy)</td><td>${aiAnalysis.compliance.gdpr}</td><td>${aiAnalysis.compliance.gdpr > 0 ? '<span class="risk-critical">FAIL</span>' : '<span class="risk-low">PASS</span>'}</td></tr>
                                <tr><td>PCI-DSS (Financial)</td><td>${aiAnalysis.compliance.pci}</td><td>${aiAnalysis.compliance.pci > 0 ? '<span class="risk-critical">FAIL</span>' : '<span class="risk-low">PASS</span>'}</td></tr>
                                <tr><td>OWASP Top 10</td><td>${aiAnalysis.compliance.owasp}</td><td>${aiAnalysis.compliance.owasp > 0 ? '<span class="risk-high">WARN</span>' : '<span class="risk-low">PASS</span>'}</td></tr>
                            </table>
                        </div>
                    </div>
                    
                    <h1>5. Actionable Threat Mitigation (All Risky IPs)</h1>
                    <p style="margin-bottom:20px; color:#64748b; font-size:13px;">The assets listed below are sorted by risk score. Any IP with a score of 5 or higher requires investigation or blocking to mitigate risk.</p>
                    ${ipToBlockRows.length > 0 ? 
                        `<table>
                            <tr><th>Asset IP</th><th>Risk Score</th><th>Critical Events</th><th>High Events</th><th>Recommended Action</th></tr>
                            ${ipToBlockRows}
                        </table>` 
                        : `<p style="color:#10b981; font-weight:700;">No high-risk external IPs detected for immediate blocking at this time. Network seems stable.</p>`
                    }


                    <h1>6. AI-Driven Remediation Plan</h1>
                    <p style="margin-bottom:20px; color:#64748b; font-size:13px;">The following tasks are prioritized by the Sentinel AI engine to address the current top risks.</p>
                    <ul class="remediation-list">
                        ${aiAnalysis.actionableSteps.map(s => `<li><strong>ACTION REQUIRED:</strong> ${s}</li>`).join('')}
                    </ul>

                    <div class="footer">
                        Generated by Sentinel AI Engine v2.4 | Confidential Security Document | Do Not Distribute Without Authorization
                    </div>
                </body>
            </html>
        `;
        
        printWindow.document.write(html);
        printWindow.document.close();
    };

    return (
        <div className="max-w-4xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card><h2 className="text-xl font-bold text-white mb-2">Raw Data Export (Excel Compatible)</h2><p className="text-slate-400 mb-6 text-sm">Download full dataset in Tab-Separated format (`.csv`) for reliable import into Excel.</p><button onClick={handleExcelExport} className="w-full border border-cyan-500 text-cyan-400 hover:bg-cyan-500 hover:text-white py-2 rounded transition-colors font-mono uppercase text-sm flex items-center justify-center gap-2">Download CSV <Download className="w-4 h-4"/></button></Card>
            <Card><h2 className="text-xl font-bold text-white mb-2">Executive Brief (Enhanced)</h2><p className="text-slate-400 mb-6 text-sm">Generate professional PDF report with forecasts, asset scores, and remediation steps.</p><button onClick={handlePrint} className="w-full border border-blue-500 text-blue-400 hover:bg-blue-500 hover:text-white py-2 rounded transition-colors font-mono uppercase text-sm flex items-center justify-center gap-2">Generate Report <Download className="w-4 h-4"/></button></Card>
        </div>
    );
};
