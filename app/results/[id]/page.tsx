"use client"

import React, { useEffect, useState } from "react"
import { useRouter, useParams } from "next/navigation"
import { createClient } from "@/lib/supabase"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { ArrowLeft, AlertTriangle, AlertCircle, CheckCircle2, Shield, Clock, Target, TrendingUp, Download, ExternalLink, Zap, Eye, EyeOff } from "lucide-react"
import Link from "next/link"

interface AnalysisResult {
  id: string
  threat_type: string
  severity: string
  summary: string
  recommendation: string
  source_ip: string
  confidence?: number
  created_at: string
}

interface LogLine {
  id: string
  line_number: number
  line_content: string
  threat_detected: boolean
  threat_type?: string
  severity?: string
  anomaly_score?: number
  pattern_matched?: string
  source_ip?: string
  destination_ip?: string
  timestamp?: string
  ai_analysis?: {
    ai_explanation?: string
    threat_indicators?: string[]
    recommended_actions?: string[]
    related_cves?: string[]
    attack_stage?: string
    confidence_score?: number
    port?: number
    http_method?: string
    status_code?: number
    is_internal_ip?: boolean
    reputation_score?: number
  }
}

export default function ResultsPage() {
  const params = useParams()
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [logLines, setLogLines] = useState<LogLine[]>([])
  const [filteredLines, setFilteredLines] = useState<LogLine[]>([])
  const [loading, setLoading] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState<string>("all")
  const [filterThreat, setFilterThreat] = useState<boolean | null>(null)
  const [searchTerm, setSearchTerm] = useState("")
  const [expandedLine, setExpandedLine] = useState<string | null>(null)
  const router = useRouter()

  // Generate summary from line analysis when main result is error
  const generateSummaryFromLines = (lines: LogLine[]): AnalysisResult => {
    const threats = lines.filter(l => l.threat_detected)
    const criticalCount = threats.filter(l => l.severity === "Critical").length
    const highCount = threats.filter(l => l.severity === "High").length
    const mediumCount = threats.filter(l => l.severity === "Medium").length

    // Determine overall severity
    let overallSeverity: "Low" | "Medium" | "High" | "Critical" = "Low"
    let threatType = "Multiple Threats Detected"
    let summary = ""
    let recommendation = ""

    if (criticalCount > 0) {
      overallSeverity = "Critical"
      threatType = "Critical Security Threats"
      summary = `${criticalCount} critical and ${highCount + mediumCount} additional security threats detected in system logs.`
      recommendation = `IMMEDIATE: Isolate affected systems and investigate critical threats\nSHORT-TERM: Review all privileged access and implement additional monitoring\nLONG-TERM: Conduct comprehensive security audit and implement advanced threat detection`
    } else if (highCount > 0) {
      overallSeverity = "High"
      threatType = "High-Risk Security Threats"
      summary = `${highCount} high-risk and ${mediumCount} medium-risk security threats detected.`
      recommendation = `IMMEDIATE: Address high-risk threats and monitor affected systems\nSHORT-TERM: Implement additional security controls and user training\nLONG-TERM: Enhance monitoring and incident response capabilities`
    } else if (mediumCount > 0) {
      overallSeverity = "Medium"
      threatType = "Security Concerns Detected"
      summary = `${mediumCount} security concerns detected requiring attention.`
      recommendation = `SHORT-TERM: Review and address identified security concerns\nLONG-TERM: Implement preventive security measures and regular monitoring`
    } else if (threats.length > 0) {
      overallSeverity = "Low"
      threatType = "Minor Security Issues"
      summary = `${threats.length} minor security issues detected.`
      recommendation = `LONG-TERM: Address minor security issues and maintain regular security practices`
    } else {
      threatType = "Clean System Logs"
      summary = "No security threats detected in the analyzed logs."
      recommendation = "Continue regular security monitoring and best practices."
    }

    // Get most common source IP from threats
    const sourceIPs = threats
      .map(t => t.source_ip)
      .filter(ip => ip && ip !== "N/A")
      .reduce((acc, ip) => {
        acc[ip] = (acc[ip] || 0) + 1
        return acc
      }, {} as Record<string, number>)

    const primaryIP = Object.entries(sourceIPs)
      .sort(([,a], [,b]) => b - a)[0]?.[0] || "Multiple sources"

    const confidence = Math.min(95, Math.max(50, 50 + (threats.length * 2)))

    return {
      id: result?.id || "generated",
      threat_type: threatType,
      severity: overallSeverity,
      summary,
      recommendation,
      source_ip: primaryIP,
      confidence,
      created_at: result?.created_at || new Date().toISOString()
    }
  }

  useEffect(() => {
    const fetchResult = async () => {
      const supabase = createClient()
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) {
        router.push("/login")
        return
      }

      const { data, error } = await supabase
        .from("analysis_results")
        .select("*")
        .eq("id", params.id)
        .eq("user_id", session.user.id)
        .single()

      let finalResult = data

      const { data: lines, error: linesError } = await supabase
        .from("log_lines")
        .select("*")
        .eq("analysis_id", params.id)
        .order("line_number", { ascending: true })

      if (lines) {
        setLogLines(lines)
        setFilteredLines(lines)

        // If main result is error or shows "Analysis Error", generate summary from lines
        if (!finalResult || finalResult.threat_type === "Analysis Error" || finalResult.summary?.includes("Could not parse")) {
          finalResult = generateSummaryFromLines(lines)
        }
      } else if (linesError) {
        console.error(linesError)
      }

      if (finalResult) {
        setResult(finalResult)
      } else if (error) {
        console.error(error)
      }

      setLoading(false)
    }

    fetchResult()
  }, [params.id, router])

  useEffect(() => {
    let filtered = [...logLines]

    if (filterThreat !== null) {
      filtered = filtered.filter(line => line.threat_detected === filterThreat)
    }

    if (filterSeverity !== "all") {
      filtered = filtered.filter(line => line.severity?.toLowerCase() === filterSeverity.toLowerCase())
    }

    if (searchTerm) {
      filtered = filtered.filter(line => 
        line.line_content.toLowerCase().includes(searchTerm.toLowerCase()) ||
        line.source_ip?.includes(searchTerm) ||
        line.threat_type?.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    setFilteredLines(filtered)
  }, [filterThreat, filterSeverity, searchTerm, logLines])

  const exportToCSV = () => {
    const headers = ["Line", "Content", "Threat", "Type", "Severity", "Score", "Confidence", "Attack Stage", "Source IP", "Dest IP", "Port", "CVEs", "Indicators"]
    const rows = filteredLines.map(line => [
      line.line_number,
      `"${line.line_content.replace(/"/g, '""')}"`,
      line.threat_detected ? "Yes" : "No",
      line.threat_type || "N/A",
      line.severity || "N/A",
      line.anomaly_score || "N/A",
      line.ai_analysis?.confidence_score || "N/A",
      line.ai_analysis?.attack_stage || "N/A",
      line.source_ip || "N/A",
      line.destination_ip || "N/A",
      line.ai_analysis?.port || "N/A",
      line.ai_analysis?.related_cves?.join('; ') || "N/A",
      line.ai_analysis?.threat_indicators?.join('; ') || "N/A"
    ])
    
    const csv = [headers, ...rows].map(row => row.join(",")).join("\n")
    const blob = new Blob([csv], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `analysis-${params.id}-lines.csv`
    a.click()
  }

  if (loading) return <div className="text-center py-8">Loading...</div>
  if (!result) return <div className="text-center py-8">Analysis not found</div>

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <AlertTriangle className="w-5 h-5 text-red-600" />
      case "high":
        return <AlertTriangle className="w-5 h-5 text-destructive" />
      case "medium":
        return <AlertCircle className="w-5 h-5 text-accent" />
      case "low":
        return <CheckCircle2 className="w-5 h-5 text-primary" />
      default:
        return <AlertCircle className="w-5 h-5" />
    }
  }

  const getSeverityColor = (severity?: string) => {
    if (!severity) return "bg-gray-50 text-gray-700 border"
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-50 text-red-700 border border-red-200"
      case "high":
        return "bg-orange-50 text-orange-700 border border-orange-200"
      case "medium":
        return "bg-yellow-50 text-yellow-700 border border-yellow-200"
      case "low":
        return "bg-green-50 text-green-700 border border-green-200"
      default:
        return "bg-gray-50 text-gray-700 border"
    }
  }

  const threatCount = logLines.filter(l => l.threat_detected).length
  const criticalCount = logLines.filter(l => l.severity === "Critical").length
  const highCount = logLines.filter(l => l.severity === "High").length
  const mediumCount = logLines.filter(l => l.severity === "Medium").length
  const lowCount = logLines.filter(l => l.severity === "Low").length
  const safeCount = logLines.length - threatCount

  return (
    <main className="min-h-screen bg-white text-gray-900">
      <nav className="bg-white border-b border-gray-200 shadow-sm px-6 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-gray-900" />
            <Link href="/" className="text-xl font-bold text-gray-900 hover:opacity-80">
              SecuAI
            </Link>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-6 py-8">
        <Button variant="outline" asChild className="mb-6 bg-white border border-gray-200 hover:bg-gray-50 transition-all duration-200">
          <Link href="/dashboard">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Link>
        </Button>

        <div className="space-y-6">
          <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 hover:scale-105 transition-all duration-200">
            <div className="pb-4">
              <div className="flex items-start justify-between">
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <Shield className="w-8 h-8 text-gray-900" />
                    <div>
                      <h2 className="text-2xl font-semibold text-gray-900 mb-3">{result.threat_type}</h2>
                      <p className="text-sm text-gray-600">Security Analysis Result</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-1">
                      <Clock className="w-4 h-4 text-gray-500" />
                      <span className="text-gray-500">Analyzed:</span>
                      <span className="font-medium">{new Date(result.created_at).toLocaleDateString()}</span>
                    </div>
                    {result.confidence && (
                      <div className="flex items-center gap-1">
                        <Target className="w-4 h-4 text-gray-500" />
                        <span className="text-gray-500">Confidence:</span>
                        <span className="font-medium">{result.confidence}%</span>
                      </div>
                    )}
                  </div>
                </div>
                <div className="text-right space-y-2">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(result.severity)}
                    <span className={`px-3 py-1 rounded-full text-sm font-semibold border ${getSeverityColor(result.severity)}`}>
                      {result.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500">
                    Threat Level
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 hover:scale-105 transition-all duration-200">
            <h3 className="text-xl font-semibold text-gray-900 mb-4">Summary</h3>
            <div className="space-y-4">
              <p className="text-gray-700 leading-relaxed">{result.summary}</p>
              {result.source_ip && (
                <div>
                  <p className="text-sm font-semibold text-gray-600">Source IP</p>
                  <p className="text-gray-900 font-mono">{result.source_ip}</p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 hover:scale-105 transition-all duration-200">
            <h3 className="text-xl font-semibold text-gray-900 mb-4 flex items-center gap-2">
              <Zap className="w-5 h-5 text-gray-900" />
              Recommended Actions
            </h3>
            <div>
              <div className="space-y-4">
                {result.recommendation.split('\n').map((line, index) => {
                  if (line.toUpperCase().includes('IMMEDIATE:')) {
                    return (
                      <div key={index} className="border-l-4 border-l-red-500 pl-4 py-2 bg-red-50 dark:bg-red-950/20">
                        <div className="flex items-center gap-2 mb-1">
                          <AlertTriangle className="w-4 h-4 text-red-600" />
                          <span className="font-semibold text-red-800 dark:text-red-400">IMMEDIATE ACTION REQUIRED</span>
                        </div>
                        <p className="text-sm text-red-700 dark:text-red-300">{line.replace('IMMEDIATE:', '').trim()}</p>
                      </div>
                    )
                  } else if (line.toUpperCase().includes('SHORT-TERM:')) {
                    return (
                      <div key={index} className="border-l-4 border-l-yellow-500 pl-4 py-2 bg-yellow-50 dark:bg-yellow-950/20">
                        <div className="flex items-center gap-2 mb-1">
                          <Clock className="w-4 h-4 text-yellow-600" />
                          <span className="font-semibold text-yellow-800 dark:text-yellow-400">SHORT-TERM FIXES</span>
                        </div>
                        <p className="text-sm text-yellow-700 dark:text-yellow-300">{line.replace('SHORT-TERM:', '').trim()}</p>
                      </div>
                    )
                  } else if (line.toUpperCase().includes('LONG-TERM:')) {
                    return (
                      <div key={index} className="border-l-4 border-l-blue-500 pl-4 py-2 bg-blue-50 dark:bg-blue-950/20">
                        <div className="flex items-center gap-2 mb-1">
                          <TrendingUp className="w-4 h-4 text-blue-600" />
                          <span className="font-semibold text-blue-800 dark:text-blue-400">LONG-TERM IMPROVEMENTS</span>
                        </div>
                        <p className="text-sm text-blue-700 dark:text-blue-300">{line.replace('LONG-TERM:', '').trim()}</p>
                      </div>
                    )
                  } else if (line.trim()) {
                    return (
                      <div key={index} className="flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-600 mt-0.5 flex-shrink-0" />
                        <p className="text-sm text-gray-900">{line.trim()}</p>
                      </div>
                    )
                  }
                  return null
                })}
              </div>
            </div>
          </div>

          {/* Statistics Overview */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-white shadow-md rounded-2xl border border-gray-200 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Target className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-900">{logLines.length}</p>
                  <p className="text-xs text-gray-600">Total Lines</p>
                </div>
              </div>
            </div>

            <div className="bg-white shadow-md rounded-2xl border border-gray-200 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-100 rounded-lg">
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-600">{threatCount}</p>
                  <p className="text-xs text-gray-600">Threats Found</p>
                </div>
              </div>
            </div>

            <div className="bg-white shadow-md rounded-2xl border border-gray-200 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-100 rounded-lg">
                  <CheckCircle2 className="w-5 h-5 text-green-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-green-600">{safeCount}</p>
                  <p className="text-xs text-gray-600">Safe Lines</p>
                </div>
              </div>
            </div>

            <div className="bg-white shadow-md rounded-2xl border border-gray-200 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-orange-100 rounded-lg">
                  <TrendingUp className="w-5 h-5 text-orange-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-orange-600">{Math.round((threatCount / logLines.length) * 100)}%</p>
                  <p className="text-xs text-gray-600">Risk Level</p>
                </div>
              </div>
            </div>
          </div>

          {/* Severity Breakdown */}
          {(criticalCount > 0 || highCount > 0 || mediumCount > 0 || lowCount > 0) && (
            <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 hover:scale-105 transition-all duration-200">
              <h3 className="text-xl font-semibold text-gray-900 mb-4">Threat Severity Breakdown</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {criticalCount > 0 && (
                  <div className="text-center p-3 bg-red-50 rounded-lg border border-red-200">
                    <AlertTriangle className="w-6 h-6 text-red-600 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-red-600">{criticalCount}</p>
                    <p className="text-xs text-red-700">Critical</p>
                  </div>
                )}
                {highCount > 0 && (
                  <div className="text-center p-3 bg-orange-50 rounded-lg border border-orange-200">
                    <AlertTriangle className="w-6 h-6 text-orange-600 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-orange-600">{highCount}</p>
                    <p className="text-xs text-orange-700">High</p>
                  </div>
                )}
                {mediumCount > 0 && (
                  <div className="text-center p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                    <AlertCircle className="w-6 h-6 text-yellow-600 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-yellow-600">{mediumCount}</p>
                    <p className="text-xs text-yellow-700">Medium</p>
                  </div>
                )}
                {lowCount > 0 && (
                  <div className="text-center p-3 bg-green-50 rounded-lg border border-green-200">
                    <CheckCircle2 className="w-6 h-6 text-green-600 mx-auto mb-1" />
                    <p className="text-2xl font-bold text-green-600">{lowCount}</p>
                    <p className="text-xs text-green-700">Low</p>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 hover:scale-105 transition-all duration-200">
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="text-xl font-semibold text-gray-900 flex items-center gap-2">
                  <Eye className="w-5 h-5 text-gray-900" />
                  Detailed Analysis
                </h3>
                <p className="text-sm text-gray-600 mt-1">
                  {logLines.length} lines analyzed • {threatCount} threats detected
                  {(criticalCount > 0 || highCount > 0) && ` • ${criticalCount + highCount} high-priority alerts`}
                </p>
              </div>
              <div className="flex gap-2">
                <Button onClick={exportToCSV} variant="outline" size="sm" className="flex items-center gap-2 bg-white border border-gray-200 hover:bg-gray-50 transition-all duration-200">
                  <Download className="w-4 h-4" />
                  Export CSV
                </Button>
              </div>
            </div>
            <div className="space-y-4">
              <div className="flex flex-wrap gap-3">
                <input
                  type="text"
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="flex-1 min-w-[200px] px-3 py-2 bg-white border border-gray-300 rounded-md text-sm text-gray-900 placeholder-gray-500 focus:border-gray-500 focus:ring-1 focus:ring-gray-500"
                />
                <select
                  value={filterThreat === null ? "all" : filterThreat ? "threats" : "safe"}
                  onChange={(e) => setFilterThreat(e.target.value === "all" ? null : e.target.value === "threats")}
                  className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm text-gray-900 focus:border-gray-500 focus:ring-1 focus:ring-gray-500"
                >
                  <option value="all">All Lines</option>
                  <option value="threats">Threats Only</option>
                  <option value="safe">Safe Only</option>
                </select>
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm text-gray-900 focus:border-gray-500 focus:ring-1 focus:ring-gray-500"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div className="border border-gray-200 rounded-xl overflow-hidden bg-white">
                <div className="max-h-[600px] overflow-y-auto">
                  <table className="min-w-full text-sm">
                    <thead className="bg-gray-50 text-gray-700 sticky top-0">
                      <tr>
                        <th className="text-left py-3 px-4 font-semibold">#</th>
                        <th className="text-left py-3 px-4 font-semibold">Log Content</th>
                        <th className="text-left py-3 px-4 font-semibold">Threat</th>
                        <th className="text-left py-3 px-4 font-semibold">Severity</th>
                        <th className="text-left py-3 px-4 font-semibold">Score</th>
                        <th className="text-left py-3 px-4 font-semibold">Stage</th>
                        <th className="text-left py-3 px-4 font-semibold">Source IP</th>
                        <th className="text-left py-3 px-4 font-semibold">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 text-gray-800">
                      {filteredLines.map((line) => (
                        <React.Fragment key={line.id}>
                          <tr
                            className={`hover:bg-gray-50 transition-colors cursor-pointer ${line.threat_detected ? 'bg-red-50' : ''}`}
                            onClick={() => setExpandedLine(expandedLine === line.id ? null : line.id)}
                          >
                            <td className="py-2 px-4 text-gray-600">{line.line_number}</td>
                            <td className="py-2 px-4 font-mono text-xs max-w-md truncate" title={line.line_content}>
                              {line.line_content}
                            </td>
                            <td className="py-2 px-4">
                              {line.threat_detected ? (
                                <span className="text-red-600 font-medium">{line.threat_type}</span>
                              ) : (
                                <span className="text-gray-600">Safe</span>
                              )}
                            </td>
                            <td className="py-2 px-4">
                              {line.severity ? (
                                <div className="flex items-center gap-1">
                                  {getSeverityIcon(line.severity)}
                                  <span className={`px-2 py-0.5 rounded text-xs border ${getSeverityColor(line.severity)}`}>
                                    {line.severity}
                                  </span>
                                </div>
                              ) : (
                                <span className="text-gray-600">-</span>
                              )}
                            </td>
                            <td className="py-2 px-4">
                              {line.anomaly_score ? (
                                <span className="font-medium text-gray-900">{line.anomaly_score.toFixed(0)}</span>
                              ) : (
                                <span className="text-gray-600">-</span>
                              )}
                            </td>
                            <td className="py-2 px-4">
                              {line.ai_analysis?.attack_stage ? (
                                <span className="text-xs px-2 py-0.5 bg-blue-100 text-blue-800 rounded border border-blue-300">
                                  {line.ai_analysis.attack_stage}
                                </span>
                              ) : (
                                <span className="text-gray-600">-</span>
                              )}
                            </td>
                            <td className="py-2 px-4 font-mono text-xs">
                              {line.source_ip || <span className="text-gray-600">-</span>}
                            </td>
                            <td className="py-2 px-4 text-center">
                              {line.threat_detected && (
                                <button className="text-primary hover:underline text-xs">
                                  {expandedLine === line.id ? "Hide" : "Show"}
                                </button>
                              )}
                            </td>
                          </tr>
                          {expandedLine === line.id && line.threat_detected && (
                            <tr key={`${line.id}-details`} className="border-t border-gray-200">
                              <td colSpan={8} className="py-6 px-4 bg-gray-50">
                                <div className="space-y-6">
                                  {line.ai_analysis?.ai_explanation && (
                                    <div>
                                      <h4 className="font-semibold text-sm mb-1 flex items-center gap-2 text-gray-900">
                                        <AlertCircle className="w-4 h-4 text-gray-900" />
                                        AI Analysis
                                      </h4>
                                      <p className="text-sm text-gray-700">{line.ai_analysis.ai_explanation}</p>
                                    </div>
                                  )}
                                  
                                  {line.ai_analysis?.threat_indicators && line.ai_analysis.threat_indicators.length > 0 && (
                                    <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                                      <h4 className="font-semibold text-sm mb-3 flex items-center gap-2 text-blue-800">
                                        <Target className="w-4 h-4 text-blue-800" />
                                        Threat Indicators
                                      </h4>
                                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                        {line.ai_analysis.threat_indicators.map((indicator, idx) => (
                                          <div key={idx} className="flex items-center gap-2 text-sm">
                                            <div className="w-2 h-2 bg-blue-500 rounded-full flex-shrink-0"></div>
                                            <span className="text-gray-700">{indicator}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {line.ai_analysis?.related_cves && line.ai_analysis.related_cves.length > 0 && (
                                    <div className="bg-red-50 p-4 rounded-lg border border-red-200">
                                      <h4 className="font-semibold text-sm mb-3 flex items-center gap-2 text-red-800">
                                        <Shield className="w-4 h-4 text-red-800" />
                                        Related Vulnerabilities
                                      </h4>
                                      <div className="flex flex-wrap gap-2">
                                        {line.ai_analysis.related_cves.map((cve, idx) => (
                                          <a
                                            key={idx}
                                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-1 px-3 py-1 bg-red-100 text-red-800 rounded-md text-xs border border-red-300 hover:bg-red-200 transition-colors"
                                          >
                                            {cve}
                                            <ExternalLink className="w-3 h-3" />
                                          </a>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {line.ai_analysis?.recommended_actions && line.ai_analysis.recommended_actions.length > 0 && (
                                    <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                                      <h4 className="font-semibold text-sm mb-3 flex items-center gap-2 text-green-800">
                                        <CheckCircle2 className="w-4 h-4 text-green-800" />
                                        Recommended Actions
                                      </h4>
                                      <ol className="space-y-2">
                                        {line.ai_analysis.recommended_actions.map((action, idx) => (
                                          <li key={idx} className="flex items-start gap-2 text-sm text-gray-700">
                                            <span className="flex-shrink-0 w-5 h-5 bg-green-100 text-green-800 rounded-full flex items-center justify-center text-xs font-medium mt-0.5">
                                              {idx + 1}
                                            </span>
                                            <span>{action}</span>
                                          </li>
                                        ))}
                                      </ol>
                                    </div>
                                  )}

                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2 border-t border-gray-200">
                                    {line.ai_analysis?.confidence_score && (
                                      <div>
                                        <p className="text-xs text-gray-600">Confidence</p>
                                        <p className="font-semibold text-gray-900">{line.ai_analysis.confidence_score}%</p>
                                      </div>
                                    )}
                                    {line.ai_analysis?.port && (
                                      <div>
                                        <p className="text-xs text-gray-600">Port</p>
                                        <p className="font-semibold font-mono text-gray-900">{line.ai_analysis.port}</p>
                                      </div>
                                    )}
                                    {line.ai_analysis?.http_method && (
                                      <div>
                                        <p className="text-xs text-gray-600">HTTP Method</p>
                                        <p className="font-semibold text-gray-900">{line.ai_analysis.http_method}</p>
                                      </div>
                                    )}
                                    {line.ai_analysis?.status_code && (
                                      <div>
                                        <p className="text-xs text-gray-600">Status Code</p>
                                        <p className="font-semibold text-gray-900">{line.ai_analysis.status_code}</p>
                                      </div>
                                    )}
                                    {line.ai_analysis?.reputation_score !== undefined && (
                                      <div>
                                        <p className="text-xs text-gray-600">IP Reputation</p>
                                        <p className="font-semibold text-gray-900">{line.ai_analysis.reputation_score}/100</p>
                                      </div>
                                    )}
                                    {line.ai_analysis?.is_internal_ip !== undefined && (
                                      <div>
                                        <p className="text-xs text-gray-600">IP Type</p>
                                        <p className="font-semibold text-gray-900">{line.ai_analysis.is_internal_ip ? "Internal" : "External"}</p>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {filteredLines.length === 0 && (
                <div className="text-center py-8 text-gray-600">
                  No log lines match your filters
                </div>
              )}
            </div>
          </div>

          <div className="bg-gray-50 border border-gray-200 rounded-2xl p-4">
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1 text-gray-600">
                  <Clock className="w-4 h-4" />
                  <span>Analysis completed on {new Date(result.created_at).toLocaleDateString()} at {new Date(result.created_at).toLocaleTimeString()}</span>
                </div>
                {result.confidence && (
                  <div className="flex items-center gap-1 text-gray-600">
                    <Target className="w-4 h-4" />
                    <span>AI Confidence: {result.confidence}%</span>
                  </div>
                )}
              </div>
              <div className="text-gray-600">
                Powered by SecuAI • Advanced Threat Detection
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}
