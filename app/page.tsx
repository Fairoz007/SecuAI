"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { createClient } from "@/lib/supabase"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { AlertCircle, Upload, Activity } from "lucide-react"

export default function Home() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null)
  const router = useRouter()
  const supabase = createClient()

  useEffect(() => {
    const checkAuth = async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      setIsAuthenticated(!!session)
      if (session) {
        router.push("/dashboard")
      }
    }
    checkAuth()
  }, [router, supabase.auth])

  if (isAuthenticated === null) {
    return null
  }

  return (
    <main className="min-h-screen bg-white text-gray-900 flex flex-col">
      <nav className="bg-white border-b border-gray-200 shadow-sm px-6 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-6 h-6 text-gray-900" />
            <h1 className="text-xl font-bold text-gray-900">SecuAI</h1>
          </div>
          <div className="flex gap-3">
            <Button variant="outline" asChild className="bg-white border border-gray-200 hover:bg-gray-50 transition-all duration-200">
              <Link href="/login">Sign In</Link>
            </Button>
            <Button asChild className="bg-blue-600 hover:bg-blue-700 text-white transition-all duration-200">
              <Link href="/signup">Get Started</Link>
            </Button>
          </div>
        </div>
      </nav>

      <div className="flex-1 flex flex-col items-center justify-center px-6 py-20">
        <div className="max-w-2xl text-center space-y-8">
          <div className="space-y-4">
            <h2 className="text-5xl font-bold text-balance text-gray-900">AI-Powered Threat Detection</h2>
            <p className="text-xl text-gray-600">
              Analyze your logs with advanced AI to detect security threats in real-time. Get instant alerts for
              high-severity risks.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 space-y-3 hover:scale-105 transition-all duration-200">
              <Upload className="w-8 h-8 text-blue-600 mx-auto" />
              <h3 className="font-semibold text-gray-900">Easy Upload</h3>
              <p className="text-sm text-gray-600">Upload or paste your system and firewall logs</p>
            </div>
            <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 space-y-3 hover:scale-105 transition-all duration-200">
              <Activity className="w-8 h-8 text-emerald-500 mx-auto" />
              <h3 className="font-semibold text-gray-900">AI Analysis</h3>
              <p className="text-sm text-gray-600">Powered by Llama 3 for intelligent threat detection</p>
            </div>
            <div className="bg-gray-50 shadow-lg rounded-2xl border border-gray-200 p-6 space-y-3 hover:scale-105 transition-all duration-200">
              <AlertCircle className="w-8 h-8 text-blue-600 mx-auto" />
              <h3 className="font-semibold text-gray-900">Instant Alerts</h3>
              <p className="text-sm text-gray-600">Email notifications for high-severity threats</p>
            </div>
          </div>

          <Button size="lg" asChild className="mt-8 bg-blue-600 hover:bg-blue-700 text-white transition-all duration-200">
            <Link href="/signup">Start Free Today</Link>
          </Button>
        </div>
      </div>
    </main>
  )
}
