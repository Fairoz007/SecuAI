"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { createClient } from "@/lib/supabase"
import { Button } from "@/components/ui/button"
import { AlertCircle, LogOut, Upload } from "lucide-react"
import Link from "next/link"
import AnalysisTable from "@/components/analysis-table"

export default function DashboardPage() {
  const [user, setUser] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    const supabase = createClient()
    const checkAuth = async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) {
        router.push("/login")
      } else {
        setUser(session.user)
      }
      setLoading(false)
    }
    checkAuth()
  }, [router])

  const handleLogout = async () => {
    const supabase = createClient()
    await supabase.auth.signOut()
    router.push("/")
  }

  if (loading) return null

  return (
    <main className="min-h-screen bg-white text-gray-900">
      <nav className="bg-white border-b border-gray-200 shadow-sm px-6 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-6 h-6 text-gray-900" />
            <h1 className="text-xl font-bold text-gray-900">SecuAI Dashboard</h1>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600">{user?.email}</span>
            <Button variant="outline" size="sm" onClick={handleLogout} className="bg-white border border-gray-200 hover:bg-gray-50 transition-all duration-200">
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-3xl font-bold text-gray-900">Analysis Results</h2>
            <p className="text-gray-600 mt-1">View and manage your log analysis history</p>
          </div>
          <Button asChild size="lg" className="bg-blue-600 hover:bg-blue-700 text-white transition-all duration-200">
            <Link href="/upload">
              <Upload className="w-4 h-4 mr-2" />
              Analyze New Log
            </Link>
          </Button>
        </div>

        <AnalysisTable />
      </div>
    </main>
  )
}
