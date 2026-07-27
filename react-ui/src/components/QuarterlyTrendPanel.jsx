import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CalendarRange } from "lucide-react";

export function QuarterlyTrendPanel({ dashboard }) {
  const trend = dashboard?.quarterlyDiscoveryTrend ?? [];
  const totalDiscovered = trend.reduce((sum, row) => sum + (Number(row.discoveredCount) || 0), 0);

  return (
    <section className="cyber-panel rounded-[1.75rem] p-5">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mini-label">Three-Month Scan View</p>
          <h2 className="mt-1 text-xl font-bold text-white">Vulnerabilities discovered in the last 3 months</h2>
          <p className="mt-1 text-sm font-semibold text-slate-500">Calculated from First Discovered in this scan export.</p>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-red-400/20 bg-red-500/[0.06] px-4 py-3">
          <CalendarRange className="h-5 w-5 text-red-300" />
          <div><p className="text-2xl font-bold text-white">{totalDiscovered.toLocaleString()}</p><p className="text-xs font-semibold text-slate-500">discovered in period</p></div>
        </div>
      </div>

      <div className="h-[310px] rounded-2xl border border-white/10 bg-black/25 p-4" role="img" aria-label={`Quarterly discovery line chart: ${trend.map((row) => `${row.month}, ${row.discoveredCount}`).join("; ")}`}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={trend} margin={{ top: 20, right: 30, bottom: 10, left: 0 }}>
            <CartesianGrid stroke="#27272a" strokeDasharray="4 5" vertical={false} />
            <XAxis dataKey="month" stroke="#71717a" tick={{ fontSize: 12, fontWeight: 600 }} />
            <YAxis allowDecimals={false} stroke="#71717a" tick={{ fontSize: 12 }} />
            <Tooltip contentStyle={{ background: "#0a0a0b", border: "1px solid #3f3f46", borderRadius: 10 }} formatter={(value) => [value, "Discovered"]} />
            <Line type="monotone" dataKey="discoveredCount" name="Discovered" stroke="#ef4444" strokeWidth={4} dot={{ r: 6, fill: "#0a0a0b", stroke: "#fb7185", strokeWidth: 3 }} activeDot={{ r: 7 }} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
