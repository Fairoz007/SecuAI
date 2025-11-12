"use client"

import { useEffect, useState } from "react"
import { createClient } from "@/lib/supabase"
import { Button } from "@/components/ui/button"
import { AlertTriangle, AlertCircle, CheckCircle2, Eye, Trash2 } from "lucide-react"
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
  ai_analysis?: any
}

export default function AnalysisTable() {
  const [results, setResults] = useState<AnalysisResult[]>([])
  const [loading, setLoading] = useState(true)

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
      summary = `${criticalCount} critical and ${highCount + mediumCount} additional security threats detected.`
      recommendation = `IMMEDIATE: Isolate affected systems and investigate critical threats`
    } else if (highCount > 0) {
      overallSeverity = "High"
      threatType = "High-Risk Security Threats"
      summary = `${highCount} high-risk and ${mediumCount} medium-risk security threats detected.`
      recommendation = `IMMEDIATE: Address high-risk threats and monitor affected systems`
    } else if (mediumCount > 0) {
      overallSeverity = "Medium"
      threatType = "Security Concerns Detected"
      summary = `${mediumCount} security concerns detected requiring attention.`
      recommendation = `SHORT-TERM: Review and address identified security concerns`
    } else if (threats.length > 0) {
      overallSeverity = "Low"
      threatType = "Minor Security Issues"
      summary = `${threats.length} minor security issues detected.`
      recommendation = `LONG-TERM: Address minor security issues`
    } else {
      threatType = "Clean System Logs"
      summary = "No security threats detected in the analyzed logs."
      recommendation = "Continue regular security monitoring."
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
      id: "generated",
      threat_type: threatType,
      severity: overallSeverity,
      summary,
      recommendation,
      source_ip: primaryIP,
      confidence,
      created_at: new Date().toISOString()
    }
  }

  useEffect(() => {
    const fetchResults = async () => {
      const supabase = createClient()
      const {
        data: { session },
      } = await supabase.auth.getSession()

      if (!session) return

      // Fetch analysis results
      const { data: analysisData, error: analysisError } = await supabase
        .from("analysis_results")
        .select("*")
        .eq("user_id", session.user.id)
        .order("created_at", { ascending: false })

      if (analysisError) {
        console.error("Error fetching analysis results:", analysisError)
        setLoading(false)
        return
      }

      // For each analysis result, check if it's an error and try to generate from lines
      const processedResults = await Promise.all(
        (analysisData || []).map(async (result) => {
          // If result is error or shows parsing issues, try to generate from lines
          if (result.threat_type === "Analysis Error" || result.summary?.includes("Could not parse")) {
            const { data: lines } = await supabase
              .from("log_lines")
              .select("*")
              .eq("analysis_id", result.id)
              .order("line_number", { ascending: true })

            if (lines && lines.length > 0) {
              const generatedResult = generateSummaryFromLines(lines)
              return {
                ...result,
                threat_type: generatedResult.threat_type,
                severity: generatedResult.severity,
                summary: generatedResult.summary,
                recommendation: generatedResult.recommendation,
                source_ip: generatedResult.source_ip,
                confidence: generatedResult.confidence
              }
            }
          }
          return result
        })
      )

      setResults(processedResults)
      setLoading(false)
    }

    fetchResults()
  }, [])

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <AlertTriangle className="w-4 h-4 text-red-600" />
      case "high":
        return <AlertTriangle className="w-4 h-4 text-orange-600" />
      case "medium":
        return <AlertCircle className="w-4 h-4 text-yellow-600" />
      case "low":
        return <CheckCircle2 className="w-4 h-4 text-green-600" />
      default:
        return <AlertCircle className="w-4 h-4" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-100 text-red-800 border-red-300"
      case "high":
        return "bg-orange-100 text-orange-800 border-orange-300"
      case "medium":
        return "bg-yellow-100 text-yellow-800 border-yellow-300"
      case "low":
        return "bg-green-100 text-green-800 border-green-300"
      default:
        return "bg-gray-100 text-gray-800 border-gray-300"
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this analysis?")) return

    const supabase = createClient()
    const { error } = await supabase
      .from("analysis_results")
      .delete()
      .eq("id", id)

    if (!error) {
      setResults(results.filter(r => r.id !== id))
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading analysis results...</p>
        </div>
      </div>
    )
  }

  if (results.length === 0) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="w-12 h-12 text-gray-500 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No Analysis Results</h3>
        <p className="text-gray-600 mb-4">You haven't analyzed any logs yet.</p>
        <Button asChild className="bg-blue-600 hover:bg-blue-700 text-white transition-all duration-200">
          <Link href="/upload">Analyze Your First Log</Link>
        </Button>
      </div>
    )
  }

  return (
    <div className="bg-gray-50 rounded-lg border border-gray-200 overflow-hidden shadow-lg">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left py-3 px-4 font-semibold text-gray-900">Threat Type</th>
              <th className="text-left py-3 px-4 font-semibold text-gray-900">Severity</th>
              <th className="text-left py-3 px-4 font-semibold text-gray-900">Summary</th>
              <th className="text-left py-3 px-4 font-semibold text-gray-900">Date</th>
              <th className="text-left py-3 px-4 font-semibold text-gray-900">Actions</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => (
              <tr key={result.id} className="border-t border-gray-200 hover:bg-gray-50">
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(result.severity)}
                    <span className="font-medium">{result.threat_type}</span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-1 rounded-full text-xs border ${getSeverityColor(result.severity)}`}>
                    {result.severity.toUpperCase()}
                  </span>
                </td>
                <td className="py-3 px-4 max-w-md">
                  <p className="text-sm text-gray-600 truncate" title={result.summary}>
                    {result.summary}
                  </p>
                </td>
                <td className="py-3 px-4 text-sm text-gray-600">
                  {new Date(result.created_at).toLocaleDateString()}
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <Button asChild variant="outline" size="sm" className="transition-all duration-200">
                      <Link href={`/results/${result.id}`}>
                        <Eye className="w-4 h-4 mr-1" />
                        View Details
                      </Link>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDelete(result.id)}
                      className="text-red-600 hover:text-red-700 hover:bg-red-50 transition-all duration-200"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}