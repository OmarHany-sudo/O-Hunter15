import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Checkbox } from '@/components/ui/checkbox.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Separator } from '@/components/ui/separator.jsx'
import { 
  Shield, 
  Zap, 
  Settings, 
  Play,
  Clock,
  Target,
  Search,
  AlertTriangle,
  Code,
  Globe,
  Lock,
  Database
} from 'lucide-react'

const ScanOptions = ({ onScanStart, isScanning = false }) => {
  const [selectedOptions, setSelectedOptions] = useState({
    // Basic scans
    headers: true,
    ssl: true,
    
    // OWASP Top 10
    sqli: false,
    xss: false,
    idor: false,
    
    // Advanced scans
    rce: false,
    xxe: false,
    ssrf: false,
    openRedirect: false,
    httpSmuggling: false,
    insecureDeserialization: false,
    
    // Reconnaissance
    dirEnum: false,
    weakCreds: false,
    portScan: false,
    serviceDetection: false,
    techStack: false
  })

  const scanPresets = {
    quick: {
      name: 'Quick Scan',
      description: 'Basic security headers and SSL configuration',
      duration: '1-2 minutes',
      icon: Zap,
      color: 'bg-green-600 hover:bg-green-700',
      options: ['headers', 'ssl', 'techStack']
    },
    full: {
      name: 'Full Scan',
      description: 'Comprehensive vulnerability assessment',
      duration: '10-15 minutes',
      icon: Shield,
      color: 'bg-blue-600 hover:bg-blue-700',
      options: ['headers', 'ssl', 'sqli', 'xss', 'idor', 'rce', 'xxe', 'ssrf', 'dirEnum', 'techStack']
    },
    custom: {
      name: 'Custom Scan',
      description: 'Select specific vulnerability checks',
      duration: 'Variable',
      icon: Settings,
      color: 'bg-purple-600 hover:bg-purple-700',
      options: Object.keys(selectedOptions)
    }
  }

  const vulnerabilityCategories = {
    basic: {
      title: 'Basic Security',
      icon: Lock,
      checks: [
        { key: 'headers', label: 'Security Headers', description: 'Check for missing security headers' },
        { key: 'ssl', label: 'SSL/TLS Configuration', description: 'Analyze SSL certificate and configuration' }
      ]
    },
    owasp: {
      title: 'OWASP Top 10',
      icon: AlertTriangle,
      checks: [
        { key: 'sqli', label: 'SQL Injection', description: 'Test for SQL injection vulnerabilities' },
        { key: 'xss', label: 'Cross-Site Scripting', description: 'Check for XSS vulnerabilities' },
        { key: 'idor', label: 'Broken Access Control', description: 'Test for IDOR vulnerabilities' }
      ]
    },
    advanced: {
      title: 'Advanced Vulnerabilities',
      icon: Code,
      checks: [
        { key: 'rce', label: 'Remote Code Execution', description: 'Test for RCE vulnerabilities' },
        { key: 'xxe', label: 'XML External Entity', description: 'Check for XXE vulnerabilities' },
        { key: 'ssrf', label: 'Server-Side Request Forgery', description: 'Test for SSRF vulnerabilities' },
        { key: 'openRedirect', label: 'Open Redirect', description: 'Check for open redirect vulnerabilities' },
        { key: 'httpSmuggling', label: 'HTTP Request Smuggling', description: 'Test for HTTP smuggling' },
        { key: 'insecureDeserialization', label: 'Insecure Deserialization', description: 'Check for deserialization flaws' }
      ]
    },
    recon: {
      title: 'Reconnaissance',
      icon: Search,
      checks: [
        { key: 'dirEnum', label: 'Directory Enumeration', description: 'Discover hidden directories and files' },
        { key: 'weakCreds', label: 'Weak Credentials', description: 'Test for common weak passwords' },
        { key: 'portScan', label: 'Port Scanning', description: 'Scan for open ports' },
        { key: 'serviceDetection', label: 'Service Detection', description: 'Identify running services' },
        { key: 'techStack', label: 'Technology Stack', description: 'Detect web technologies and frameworks' }
      ]
    }
  }

  const handlePresetScan = (presetKey) => {
    const preset = scanPresets[presetKey]
    if (presetKey === 'custom') {
      // For custom scan, use currently selected options
      onScanStart(selectedOptions, presetKey)
    } else {
      // For quick/full scan, use preset options
      const presetOptions = {}
      preset.options.forEach(option => {
        presetOptions[option] = true
      })
      onScanStart(presetOptions, presetKey)
    }
  }

  const handleOptionChange = (optionKey, checked) => {
    setSelectedOptions(prev => ({
      ...prev,
      [optionKey]: checked
    }))
  }

  const getSelectedCount = () => {
    return Object.values(selectedOptions).filter(Boolean).length
  }

  return (
    <div className="space-y-6">
      {/* Scan Presets */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center space-x-2">
            <Target className="h-5 w-5" />
            <span>Scan Presets</span>
          </CardTitle>
          <CardDescription className="text-slate-400">
            Choose a predefined scanning configuration
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(scanPresets).map(([key, preset]) => {
              const IconComponent = preset.icon
              return (
                <Card key={key} className="bg-slate-700/50 border-slate-600 hover:bg-slate-700/70 transition-colors">
                  <CardHeader className="pb-3">
                    <div className="flex items-center space-x-2">
                      <IconComponent className="h-5 w-5 text-blue-400" />
                      <CardTitle className="text-lg text-white">{preset.name}</CardTitle>
                    </div>
                    <CardDescription className="text-slate-400">
                      {preset.description}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-4 w-4 text-slate-400" />
                      <span className="text-sm text-slate-300">{preset.duration}</span>
                    </div>
                    <Button
                      onClick={() => handlePresetScan(key)}
                      disabled={isScanning}
                      className={`w-full ${preset.color} text-white`}
                    >
                      <Play className="h-4 w-4 mr-2" />
                      Start {preset.name}
                    </Button>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* Custom Scan Options */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Settings className="h-5 w-5" />
              <span>Custom Scan Configuration</span>
            </div>
            <Badge variant="outline" className="border-slate-600 text-slate-300">
              {getSelectedCount()} selected
            </Badge>
          </CardTitle>
          <CardDescription className="text-slate-400">
            Select specific vulnerability checks to perform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {Object.entries(vulnerabilityCategories).map(([categoryKey, category]) => {
            const IconComponent = category.icon
            return (
              <div key={categoryKey} className="space-y-3">
                <div className="flex items-center space-x-2">
                  <IconComponent className="h-5 w-5 text-blue-400" />
                  <h3 className="text-lg font-semibold text-white">{category.title}</h3>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 ml-7">
                  {category.checks.map((check) => (
                    <div key={check.key} className="flex items-start space-x-3 p-3 bg-slate-700/30 rounded-lg">
                      <Checkbox
                        id={check.key}
                        checked={selectedOptions[check.key]}
                        onCheckedChange={(checked) => handleOptionChange(check.key, checked)}
                        className="mt-1"
                      />
                      <div className="space-y-1">
                        <Label
                          htmlFor={check.key}
                          className="text-white font-medium cursor-pointer"
                        >
                          {check.label}
                        </Label>
                        <p className="text-sm text-slate-400">{check.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
                {categoryKey !== 'recon' && <Separator className="bg-slate-600" />}
              </div>
            )
          })}
        </CardContent>
      </Card>
    </div>
  )
}

export default ScanOptions

