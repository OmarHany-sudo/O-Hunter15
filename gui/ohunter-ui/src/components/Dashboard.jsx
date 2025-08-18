import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import { Progress } from '@/components/ui/progress.jsx'
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line
} from 'recharts'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  TrendingUp,
  Activity,
  Target,
  Clock,
  Download,
  Play,
  Settings
} from 'lucide-react'

const Dashboard = ({ scanResults = [], scanInfo = null }) => {
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0
  })

  useEffect(() => {
    if (scanResults.length > 0) {
      const newStats = scanResults.reduce((acc, result) => {
        const severity = result.severity.toLowerCase()
        acc.total++
        acc[severity] = (acc[severity] || 0) + 1
        return acc
      }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 })
      
      setStats(newStats)
    }
  }, [scanResults])

  const severityData = [
    { name: 'Critical', value: stats.critical, color: '#dc2626' },
    { name: 'High', value: stats.high, color: '#ea580c' },
    { name: 'Medium', value: stats.medium, color: '#ca8a04' },
    { name: 'Low', value: stats.low, color: '#2563eb' },
    { name: 'Info', value: stats.informational, color: '#6b7280' }
  ].filter(item => item.value > 0)

  const vulnerabilityTypes = scanResults.reduce((acc, result) => {
    const type = result.vulnerability.split(' ')[0] // Get first word as type
    acc[type] = (acc[type] || 0) + 1
    return acc
  }, {})

  const typeData = Object.entries(vulnerabilityTypes).map(([name, count]) => ({
    name,
    count
  }))

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-600 text-white'
      case 'high': return 'bg-red-500 text-white'
      case 'medium': return 'bg-yellow-500 text-white'
      case 'low': return 'bg-blue-500 text-white'
      case 'informational': return 'bg-gray-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getRiskScore = () => {
    const weights = { critical: 10, high: 7, medium: 4, low: 2, informational: 1 }
    const totalScore = Object.entries(stats).reduce((acc, [severity, count]) => {
      return acc + (weights[severity] || 0) * count
    }, 0)
    return Math.min(100, Math.round((totalScore / (stats.total * 10)) * 100))
  }

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-white">Total Findings</CardTitle>
            <Target className="h-4 w-4 text-slate-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
            <p className="text-xs text-slate-400">
              Vulnerabilities detected
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-white">Risk Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-slate-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{getRiskScore()}/100</div>
            <Progress value={getRiskScore()} className="mt-2" />
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-white">Critical Issues</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{stats.critical}</div>
            <p className="text-xs text-slate-400">
              Require immediate attention
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-white">Scan Status</CardTitle>
            <Activity className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">Complete</div>
            <p className="text-xs text-slate-400">
              {scanInfo?.target_url || 'No target'}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Severity Distribution</CardTitle>
            <CardDescription className="text-slate-400">
              Breakdown of vulnerabilities by severity level
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Vulnerability Types */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Vulnerability Types</CardTitle>
            <CardDescription className="text-slate-400">
              Most common vulnerability categories
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={typeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1f2937', 
                    border: '1px solid #374151',
                    borderRadius: '6px'
                  }}
                />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white">Quick Actions</CardTitle>
          <CardDescription className="text-slate-400">
            Common scanning options and report generation
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button className="bg-blue-600 hover:bg-blue-700 text-white">
              <Play className="h-4 w-4 mr-2" />
              Quick Scan
            </Button>
            <Button className="bg-orange-600 hover:bg-orange-700 text-white">
              <Shield className="h-4 w-4 mr-2" />
              Full Scan
            </Button>
            <Button className="bg-purple-600 hover:bg-purple-700 text-white">
              <Settings className="h-4 w-4 mr-2" />
              Custom Scan
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Recent Findings */}
      {scanResults.length > 0 && (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Recent Findings</CardTitle>
            <CardDescription className="text-slate-400">
              Latest vulnerabilities discovered
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {scanResults.slice(0, 5).map((result, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                    <div>
                      <p className="text-white font-medium">{result.vulnerability}</p>
                      <p className="text-slate-400 text-sm">{result.evidence.substring(0, 60)}...</p>
                    </div>
                  </div>
                  <Badge className={getSeverityColor(result.severity)}>
                    {result.severity}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default Dashboard

