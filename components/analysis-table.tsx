"use client"

import { useEffect, useState } from "react"
import { createClient } from "@/lib/supabase"
import { Card } from "@/components/ui/card"
import Link from "next/link"
import { format } from "date-fns"
import { AlertTriangle, AlertCircle, CheckCircle2 } from "lucide-react"

interface Analysis {
  id: string
  created_at: string
  threat_type: string
  severity: string
  summary: string
}

export default function AnalysisTable() {
  const [analyses, setAnalyses] = useState<Analysis[]>([])
  const [loading, setLoading] = useState(true)
  const supabase = createClient()

  useEffect(() => {
    const fetchAnalyses = async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) return

      const { data, error } = await supabase
        .from("analysis_results")
        .select("id, created_at, threat_type, severity, summary")
        .eq("user_id", session.user.id)
        .order("created_at", { ascending: false })
        .limit(10)

      if (!error && data) {
        setAnalyses(data)
      }
      setLoading(false)
    }

    fetchAnalyses()
  }, [supabase])

  if (loading) {
    return <div className="text-center py-8 text-gray-600">Loading analyses...</div>
  }

  if (analyses.length === 0) {
    return (
      <div className="bg-white shadow-md rounded-2xl border border-gray-200 p-8 text-center">
        <p className="text-gray-600">No analyses yet. Start by uploading a log file.</p>
      </div>
    )
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <AlertTriangle className="w-5 h-5 text-red-600" />
      case "high":
        return <AlertTriangle className="w-5 h-5 text-orange-600" />
      case "medium":
        return <AlertCircle className="w-5 h-5 text-yellow-600" />
      case "low":
        return <CheckCircle2 className="w-5 h-5 text-green-600" />
      default:
        return <AlertCircle className="w-5 h-5" />
    }
  }

  const getSeverityColor = (severity: string) => {
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
        return "bg-gray-50 text-gray-700 border border-gray-200"
    }
  }

  return (
    <div className="bg-white shadow-md rounded-2xl border border-gray-200 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full">
          <thead className="bg-gray-50 text-gray-700">
            <tr>
              <th className="text-left py-3 px-4 font-semibold text-sm">Threat Type</th>
              <th className="text-left py-3 px-4 font-semibold text-sm">Severity</th>
              <th className="text-left py-3 px-4 font-semibold text-sm">Summary</th>
              <th className="text-left py-3 px-4 font-semibold text-sm">Date</th>
              <th className="text-left py-3 px-4 font-semibold text-sm">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 text-gray-800">
            {analyses.map((analysis) => (
              <tr key={analysis.id} className="hover:bg-gray-50 transition-colors">
                <td className="py-4 px-4 text-gray-900">{analysis.threat_type}</td>
                <td className="py-4 px-4">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(analysis.severity)}
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(analysis.severity)}`}
                    >
                      {analysis.severity}
                    </span>
                  </div>
                </td>
                <td className="py-4 px-4 text-sm text-gray-600 max-w-xs truncate">{analysis.summary}</td>
                <td className="py-4 px-4 text-sm text-gray-600">
                  {format(new Date(analysis.created_at), "MMM dd, yyyy HH:mm")}
                </td>
                <td className="py-4 px-4">
                  <Link href={`/results/${analysis.id}`} className="text-gray-900 hover:underline text-sm font-medium">
                    View Details
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
