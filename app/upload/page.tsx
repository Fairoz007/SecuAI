"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { createClient } from "@/lib/supabase"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertCircle, ArrowLeft, Loader2 } from "lucide-react"
import Link from "next/link"

export default function UploadPage() {
  const [logText, setLogText] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [authLoading, setAuthLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    const supabase = createClient()
    const checkAuth = async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) {
        router.push("/login")
      }
      setAuthLoading(false)
    }
    checkAuth()
  }, [router])

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!logText.trim()) {
      setError("Please enter log content")
      return
    }

    setLoading(true)

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logText }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Analysis failed")
      }

      router.push(`/results/${data.analysisId}`)
    } catch (err: any) {
      setError(err.message || "An error occurred during analysis")
    } finally {
      setLoading(false)
    }
  }

  if (authLoading) return null

  return (
    <main className="min-h-screen bg-white text-gray-900">
      <nav className="bg-white border-b border-gray-200 shadow-sm px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center gap-2">
          <AlertCircle className="w-6 h-6 text-gray-900" />
          <Link href="/" className="text-xl font-bold hover:opacity-80">
            SecuAI
          </Link>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-6 py-8">
        <Button variant="outline" asChild className="mb-6 bg-white border border-gray-200 hover:bg-gray-50 transition-all duration-200">
          <Link href="/dashboard">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Link>
        </Button>

        <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200">
          <div className="p-6">
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Analyze Security Logs</h2>
            <p className="text-gray-600 mb-6">
              Paste your system or firewall logs below. Our AI will analyze them for security threats.
            </p>
            <form onSubmit={handleAnalyze} className="space-y-4">
              {error && (
                <div className="bg-destructive/10 border border-destructive/50 text-destructive px-4 py-3 rounded-md text-sm">
                  {error}
                </div>
              )}
              <div className="space-y-2">
                <label htmlFor="logs" className="text-sm font-medium text-gray-900">
                  Log Content
                </label>
                <textarea
                  id="logs"
                  value={logText}
                  onChange={(e) => setLogText(e.target.value)}
                  placeholder="Paste your system logs, firewall logs, or security events here..."
                  className="w-full h-64 px-4 py-3 bg-white text-gray-900 border border-gray-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 resize-none transition-all duration-200"
                  disabled={loading}
                />
                <p className="text-xs text-gray-500">
                  Supported formats: Syslog, Windows Event Logs, Firewall Logs, Apache/Nginx Logs
                </p>
              </div>
              <Button type="submit" disabled={loading} className="w-full bg-blue-600 hover:bg-blue-700 text-white transition-all duration-200">
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing with AI...
                  </>
                ) : (
                  "Analyze Logs"
                )}
              </Button>
            </form>
          </div>
        </div>
      </div>
    </main>
  )
}
