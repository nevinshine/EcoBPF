import { useEffect, useState, useRef, useCallback } from 'react'
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts'
import {
  Leaf, Zap, Activity, Cpu, Server, LayoutGrid, BarChart2
} from 'lucide-react'
import './index.css'

/* ─── Types matching Go WebSocket payload ─────────── */
interface ProcessTelemetry {
  pid: number
  comm: string
  container_id?: string
  container_name?: string
  energy_joules: number
  power_watts: number
  carbon_grams_co2: number
  cpu_energy_joules: number
  memory_energy_joules: number
  gpu_energy_joules: number
  confidence: number
  is_ai_workload: boolean
}

interface SystemSummary {
  total_energy_joules: number
  total_power_watts: number
  total_carbon_grams_co2: number
  tracked_processes: number
  ai_workload_count: number
  container_count: number
  avg_confidence: number
}

interface TelemetryEvent {
  timestamp: string
  type: string
  process_data: ProcessTelemetry[]
  summary: SystemSummary
}

interface TimePoint {
  time: string
  energy: number
  power: number
  carbon: number
}

const WS_URL = `ws://${window.location.hostname || 'localhost'}:8080/ws`
const MAX_HISTORY = 14
const RECONNECT_DELAY = 3000
const PIE_COLORS = ['#27282c', '#a1a1aa', '#e5e7eb']

/* ─── Main App ────────────────────────────────────── */

export default function App() {
  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [latest, setLatest] = useState<TelemetryEvent | null>(null)
  const [history, setHistory] = useState<TimePoint[]>([])
  const [demoMode, setDemoMode] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<number | undefined>(undefined)
  const demoTimer = useRef<number | undefined>(undefined)

  /* ─── WebSocket Connection ────────────────────── */
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    setStatus('connecting')

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setStatus('connected')
      setDemoMode(false)
      if (demoTimer.current) clearInterval(demoTimer.current)
    }

    ws.onmessage = (evt) => {
      try {
        const data: TelemetryEvent = JSON.parse(evt.data)
        if (data.type === 'telemetry') {
          setLatest(data)
          const now = new Date(data.timestamp).toLocaleTimeString('en-US', {
            hour12: false, hour: '2-digit', minute: '2-digit'
          })

          setHistory(prev => {
            const next = [...prev, {
              time: now,
              energy: data.summary.total_energy_joules,
              power: data.summary.total_power_watts,
              carbon: data.summary.total_carbon_grams_co2,
            }]
            return next.slice(-MAX_HISTORY)
          })
        }
      } catch { /* ignore bad frames */ }
    }

    ws.onclose = () => {
      setStatus('disconnected')
      reconnectTimer.current = window.setTimeout(connect, RECONNECT_DELAY)
      if (!demoMode) startDemo()
    }

    ws.onerror = () => ws.close()
  }, [demoMode])

  /* ─── Demo Mode (synthetic data) ──────────────── */
  const startDemo = useCallback(() => {
    setDemoMode(true)
    const genData = (): TelemetryEvent => {
      const procs: ProcessTelemetry[] = [
        { pid: 1234, comm: 'python3', energy_joules: 0.8 + Math.random() * 0.5, power_watts: 0.8 + Math.random() * 0.5, carbon_grams_co2: 0.0001, cpu_energy_joules: 0.5, memory_energy_joules: 0.2, gpu_energy_joules: 0.1, confidence: 0.85, is_ai_workload: true, container_id: 'abc', container_name: 'ml-trainer' },
        { pid: 5678, comm: 'node', energy_joules: 0.3 + Math.random() * 0.2, power_watts: 0.3 + Math.random() * 0.2, carbon_grams_co2: 0.00005, cpu_energy_joules: 0.25, memory_energy_joules: 0.05, gpu_energy_joules: 0, confidence: 0.82, is_ai_workload: false, container_id: 'xyz', container_name: 'web-api' },
        { pid: 9012, comm: 'postgres', energy_joules: 0.15 + Math.random() * 0.1, power_watts: 0.15 + Math.random() * 0.1, carbon_grams_co2: 0.00003, cpu_energy_joules: 0.1, memory_energy_joules: 0.05, gpu_energy_joules: 0, confidence: 0.78, is_ai_workload: false },
      ]
      const totalE = procs.reduce((s, p) => s + p.energy_joules, 0)
      const totalP = procs.reduce((s, p) => s + p.power_watts, 0)
      const totalC = procs.reduce((s, p) => s + p.carbon_grams_co2, 0)
      return {
        timestamp: new Date().toISOString(),
        type: 'telemetry',
        process_data: procs,
        summary: {
          total_energy_joules: totalE,
          total_power_watts: totalP,
          total_carbon_grams_co2: totalC,
          tracked_processes: procs.length,
          ai_workload_count: 1,
          container_count: 2,
          avg_confidence: 0.82,
        }
      }
    }

    const seed: TimePoint[] = []
    for (let i = 14; i > 0; i--) {
      const d = genData()
      seed.push({
        time: new Date(Date.now() - i * 1000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
        energy: d.summary.total_energy_joules,
        power: d.summary.total_power_watts,
        carbon: d.summary.total_carbon_grams_co2,
      })
    }
    setHistory(seed)
    setLatest(genData())

    demoTimer.current = window.setInterval(() => {
      const data = genData()
      setLatest(data)
      const now = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' })
      setHistory(prev => {
        const next = [...prev, {
          time: now,
          energy: data.summary.total_energy_joules,
          power: data.summary.total_power_watts,
          carbon: data.summary.total_carbon_grams_co2,
        }]
        return next.slice(-MAX_HISTORY)
      })
    }, 1000)
  }, [])

  useEffect(() => {
    connect()
    return () => {
      wsRef.current?.close()
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (demoTimer.current) clearInterval(demoTimer.current)
    }
  }, [connect])

  const summary = latest?.summary
  const processes = latest?.process_data?.slice().sort((a, b) => b.energy_joules - a.energy_joules) ?? []

  const pieData = [
    { name: 'CPU Scheduling', value: 5.4 },
    { name: 'GPU Activity', value: 3.1 },
    { name: 'Page Faults', value: 0.8 },
  ]

  return (
    <div className="dashboard-layout">
      {/* ─── Sidebar ───────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Leaf size={20} color="#10b981" />
          <span>EcoBPF</span>
        </div>
        
        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Observability Engine</div>
            <a className="nav-item active">
              <LayoutGrid size={18} /> Live Telemetry
            </a>
            <a className="nav-item">
              <Cpu size={18} /> eBPF Probes
            </a>
            <a className="nav-item">
              <Server size={18} /> AI Workloads
            </a>
          </div>

          <div className="nav-section">
            <div className="nav-section-title">Node Integration</div>
            <a className="nav-item">
              <Zap size={18} /> Bare-Metal
            </a>
            <a className="nav-item">
              <Activity size={18} /> Virtualized Cloud
            </a>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div style={{ fontSize: 11, color: 'var(--text-sidebar)', opacity: 0.6, lineHeight: 1.5, padding: '0 8px' }}>
            Kernel-Level Carbon Observability for AI & Cloud Workloads
          </div>
        </div>
      </aside>

      {/* ─── Main Content ──────────────────────────────── */}
      <main className="main-content">
        <div className="top-banner">
          <div className="banner-left">
            <h1>GreenOps Resource Dashboard</h1>
            <p>Real-time per-process energy estimation via deterministic eBPF kernel signals.</p>
          </div>
          <div className="banner-right">
            <div className={`connection-status ${status}`}>
              {status === 'connected' ? 'eBPF Daemon Live' : demoMode ? 'Demo Fallback' : 'Connecting to Daemon...'}
            </div>
          </div>
        </div>

        {/* Stats Row */}
        <div className="stats-row">
          <div className="stat-card dark">
            <div className="stat-header">
              <div className="stat-icon"><Zap size={20} /></div>
              <span className="stat-title">Total Energy</span>
            </div>
            <div className="stat-value">{(summary?.total_energy_joules ?? 0).toFixed(2)} J</div>
            <div className="stat-trend trend-up">
              <Activity size={14} /> +0.4% <span className="stat-subtitle">since last hour</span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <div className="stat-icon"><BarChart2 size={20} /></div>
              <span className="stat-title">Power Draw</span>
            </div>
            <div className="stat-value">{(summary?.total_power_watts ?? 0).toFixed(2)} W</div>
            <div className="stat-trend trend-down">
              <Activity size={14} /> -1.2% <span className="stat-subtitle">avg time: 4:30m</span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <div className="stat-icon"><Leaf size={20} /></div>
              <span className="stat-title">Carbon Footprint</span>
            </div>
            <div className="stat-value">{((summary?.total_carbon_grams_co2 ?? 0) * 1000).toFixed(2)} mg</div>
            <div className="stat-trend trend-down">
              <Activity size={14} /> -12.7% <span className="stat-subtitle">grid intensive</span>
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="charts-row">
          <div className="chart-card">
            <div className="chart-header">
              <span className="chart-title">Estimated Joule Consumption</span>
              <span style={{ fontSize: 13, background: '#f3f4f6', padding: '4px 12px', borderRadius: 6 }}>Last 14 Days</span>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={history}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="time" axisLine={false} tickLine={false} />
                <YAxis axisLine={false} tickLine={false} />
                <Tooltip cursor={{ stroke: '#e5e7eb', strokeWidth: 1 }} contentStyle={{ borderRadius: 8, border: 'none', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }} />
                <Area type="monotone" dataKey="energy" stroke="#1f2937" fill="#f3f4f6" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="chart-card">
            <div className="chart-header">
              <span className="chart-title">eBPF Telemetry Breakdown</span>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%" cy="50%"
                  innerRadius={65} outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} stroke="none" />
                  ))}
                </Pie>
                <Tooltip />
                <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle" style={{ fontSize: 20, fontWeight: 700, fill: '#1f2937' }}>
                  9.3J
                </text>
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Table below everything */}
        <div className="table-card">
          <div className="chart-header">
            <span className="chart-title">Per-Process Energy Attribution</span>
          </div>
          <table className="process-table">
            <thead>
              <tr>
                <th>Process</th>
                <th>Energy (Joules)</th>
                <th>Power (Watts)</th>
                <th>Container</th>
                <th>AI Task</th>
              </tr>
            </thead>
            <tbody>
              {processes.slice(0, 5).map((p, i) => (
                <tr key={i}>
                  <td>
                    {p.comm} <span className="pid-tag">#{p.pid}</span>
                  </td>
                  <td style={{ fontWeight: 600 }}>{p.energy_joules.toFixed(3)}</td>
                  <td>{p.power_watts.toFixed(3)}</td>
                  <td>{p.container_name || 'System Workload'}</td>
                  <td>
                    {p.is_ai_workload ? (
                      <span style={{ background: '#dbeafe', color: '#1e3a8a', padding: '2px 8px', borderRadius: 10, fontSize: 11, fontWeight: 600 }}>AI Inference</span>
                    ) : (
                      <span style={{ color: '#9ca3af', fontSize: 12 }}>Standard</span>
                    )}
                  </td>
                </tr>
              ))}
              {processes.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: '#9ca3af', padding: '32px 0' }}>
                    Awaiting eBPF telemetry feeds...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  )
}
