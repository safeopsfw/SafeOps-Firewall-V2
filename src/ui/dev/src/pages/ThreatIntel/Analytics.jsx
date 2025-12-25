import { useState } from 'react';
import { BarChart3, PieChart, TrendingUp, Calendar } from 'lucide-react';

// Mock chart data
const threatTrends = [
  { date: 'Jan 1', malware: 120, phishing: 80, c2: 45, spam: 30 },
  { date: 'Jan 2', malware: 140, phishing: 95, c2: 52, spam: 28 },
  { date: 'Jan 3', malware: 110, phishing: 70, c2: 48, spam: 35 },
  { date: 'Jan 4', malware: 180, phishing: 120, c2: 60, spam: 42 },
  { date: 'Jan 5', malware: 160, phishing: 90, c2: 55, spam: 38 },
  { date: 'Jan 6', malware: 200, phishing: 140, c2: 70, spam: 45 },
  { date: 'Jan 7', malware: 175, phishing: 110, c2: 62, spam: 40 },
];

const threatDistribution = [
  { type: 'Malware', count: 45231, percentage: 42, color: '#ef4444' },
  { type: 'Phishing', count: 28456, percentage: 26, color: '#f59e0b' },
  { type: 'C2 Servers', count: 18234, percentage: 17, color: '#3b82f6' },
  { type: 'Spam', count: 12847, percentage: 12, color: '#10b981' },
  { type: 'Other', count: 3458, percentage: 3, color: '#6b7280' },
];

const topSources = [
  { name: 'AlienVault OTX', count: 45231, percentage: 85 },
  { name: 'Abuse.ch', count: 38124, percentage: 72 },
  { name: 'VirusTotal', count: 31256, percentage: 59 },
  { name: 'Emerging Threats', count: 24567, percentage: 46 },
  { name: 'PhishTank', count: 18934, percentage: 36 },
];

export default function Analytics() {
  const [timeRange, setTimeRange] = useState('7d');

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Analytics</h1>
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-dark-400" />
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Threat Trends Chart */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-6">
            <TrendingUp className="w-5 h-5 text-primary-400" />
            <h2 className="text-lg font-semibold text-white">Threat Trends</h2>
          </div>
          
          {/* Simple bar chart representation */}
          <div className="space-y-4">
            {threatTrends.slice(-5).map((day, idx) => (
              <div key={idx}>
                <div className="flex items-center justify-between text-sm mb-1">
                  <span className="text-dark-400">{day.date}</span>
                  <span className="text-white">{day.malware + day.phishing + day.c2 + day.spam}</span>
                </div>
                <div className="flex h-6 bg-dark-700 rounded-lg overflow-hidden">
                  <div className="bg-red-500" style={{ width: `${(day.malware / 400) * 100}%` }} />
                  <div className="bg-yellow-500" style={{ width: `${(day.phishing / 400) * 100}%` }} />
                  <div className="bg-blue-500" style={{ width: `${(day.c2 / 400) * 100}%` }} />
                  <div className="bg-green-500" style={{ width: `${(day.spam / 400) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-6 pt-4 border-t border-dark-700">
            <span className="flex items-center gap-2 text-sm text-dark-300">
              <span className="w-3 h-3 bg-red-500 rounded" /> Malware
            </span>
            <span className="flex items-center gap-2 text-sm text-dark-300">
              <span className="w-3 h-3 bg-yellow-500 rounded" /> Phishing
            </span>
            <span className="flex items-center gap-2 text-sm text-dark-300">
              <span className="w-3 h-3 bg-blue-500 rounded" /> C2
            </span>
            <span className="flex items-center gap-2 text-sm text-dark-300">
              <span className="w-3 h-3 bg-green-500 rounded" /> Spam
            </span>
          </div>
        </div>

        {/* Threat Distribution */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-6">
            <PieChart className="w-5 h-5 text-primary-400" />
            <h2 className="text-lg font-semibold text-white">Threat Distribution</h2>
          </div>

          {/* Donut chart representation */}
          <div className="flex items-center gap-8">
            <div className="relative w-40 h-40">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                {threatDistribution.reduce((acc, item, idx) => {
                  const offset = acc.offset;
                  const circumference = 2 * Math.PI * 35;
                  const strokeDasharray = (item.percentage / 100) * circumference;
                  acc.elements.push(
                    <circle
                      key={idx}
                      cx="50"
                      cy="50"
                      r="35"
                      fill="none"
                      stroke={item.color}
                      strokeWidth="20"
                      strokeDasharray={`${strokeDasharray} ${circumference}`}
                      strokeDashoffset={-offset}
                    />
                  );
                  acc.offset += strokeDasharray;
                  return acc;
                }, { elements: [], offset: 0 }).elements}
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-2xl font-bold text-white">108K</div>
                  <div className="text-dark-400 text-xs">Total</div>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              {threatDistribution.map((item) => (
                <div key={item.type} className="flex items-center gap-3">
                  <span className="w-3 h-3 rounded" style={{ backgroundColor: item.color }} />
                  <span className="text-dark-300 text-sm flex-1">{item.type}</span>
                  <span className="text-white font-medium">{item.percentage}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Top Sources */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-6">
          <BarChart3 className="w-5 h-5 text-primary-400" />
          <h2 className="text-lg font-semibold text-white">Top Feed Sources</h2>
        </div>

        <div className="space-y-4">
          {topSources.map((source, idx) => (
            <div key={source.name}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-white">{source.name}</span>
                <span className="text-dark-400">{source.count.toLocaleString()} records</span>
              </div>
              <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-primary-500 rounded-full"
                  style={{ width: `${source.percentage}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
