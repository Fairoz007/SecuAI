/**
 * 🚨 SecuAI Threat Analysis API – Stable v3
 * ------------------------------------------
 *  • Authenticates via Supabase
 *  • Sends logs to Ollama AI for analysis
 *  • Stores results in Supabase
 *  • Emails High/Critical alerts via SMTP
 */

import { createServerSupabaseClient } from "@/lib/supabase-server"
import { type NextRequest, NextResponse } from "next/server"
import nodemailer from "nodemailer"

export interface LlamaResponse {
  threat_type: string
  severity: "Low" | "Medium" | "High" | "Critical"
  summary: string
  recommendation: string
  source_ip: string
  confidence?: number
}

export interface LogLineAnalysis {
  line_number: number
  line_content: string
  threat_detected: boolean
  threat_type?: string
  severity?: "Low" | "Medium" | "High" | "Critical"
  anomaly_score?: number
  pattern_matched?: string
  source_ip?: string
  destination_ip?: string
  timestamp?: string
  explanation?: string
  ai_explanation?: string
  threat_indicators?: string[]
  recommended_actions?: string[]
  related_cves?: string[]
  attack_stage?: string
  confidence_score?: number
  port?: number
  protocol?: string
  user_agent?: string
  http_method?: string
  status_code?: number
  payload_size?: number
  geographic_location?: string
  is_internal_ip?: boolean
  reputation_score?: number
}

export async function POST(request: NextRequest) {
  try {
    const { logText } = await request.json()

    if (!logText) {
      return NextResponse.json({ error: "Log text is required" }, { status: 400 })
    }

    // ✅ Connect Supabase
    const supabase = await createServerSupabaseClient()
    const {
      data: { session },
    } = await supabase.auth.getSession()

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    // ✅ AI Configuration
    const useCloudAI = process.env.USE_OPENROUTER === "true"
    const aiEndpoint = useCloudAI
      ? "https://openrouter.ai/api/v1/chat/completions"
      : "http://localhost:11434/api/generate"
    
    const aiModel = process.env.OPENROUTER_MODEL || "meta-llama/llama-3-8b-instruct"
    console.log("🧠 Using AI model:", aiModel)

    // ✅ Prompt (simple & effective)
    const analysisPrompt = `Analyze the following logs and identify the MOST SEVERE threat.

IMPORTANT: Return ONLY a single valid JSON object (not an array) with no additional text, explanations, or markdown formatting.

For the "recommendation" field, provide SPECIFIC, ACTIONABLE steps including:
- Immediate measures to contain the threat
- Short-term fixes to mitigate risk
- Long-term security improvements

Required JSON format:
{
  "threat_type": "None | Brute Force | Privilege Escalation | Port Scan | Malware Communication | Data Exfiltration | Unauthorized Access | Other",
  "severity": "Low | Medium | High | Critical",
  "summary": "Brief summary of the most severe detected threat or confirmation of safety.",
  "source_ip": "Primary threat IP or 'N/A'",
  "recommendation": "IMMEDIATE: Block IP, isolate system\\nSHORT-TERM: Enable 2FA, update policies\\nLONG-TERM: Implement monitoring, regular audits",
  "confidence": 0-100
}

If multiple threats exist, focus on the most critical one. Return only the JSON object, nothing else.

Logs:
${logText}`

    // ✅ Send request to OpenRouter
    const aiResponse = await fetch(aiEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
      },
      body: JSON.stringify({
        model: aiModel,
        messages: [
          {
            role: "system",
            content:
              "You are SecuAI, an advanced cybersecurity threat analyst. Respond ONLY in valid JSON per schema.",
          },
          {
            role: "user",
            content: analysisPrompt,
          },
        ],
        temperature: 0.1,
        max_tokens: 800,
      }),
    })

    if (!aiResponse.ok) {
      const error = await aiResponse.text()
      console.error("❌ OpenRouter error:", error)
      throw new Error(`OpenRouter API error: ${error}`)
    }

    const aiData = await aiResponse.json()
    const responseText = aiData?.choices?.[0]?.message?.content || ""

    let analysis: LlamaResponse
    try {
      // Clean and extract JSON from AI response
      let jsonText = responseText.trim()

      // Remove markdown code blocks if present
      if (jsonText.startsWith('```json')) {
        jsonText = jsonText.replace(/^```json\s*/, '').replace(/\s*```$/, '')
      } else if (jsonText.startsWith('```')) {
        jsonText = jsonText.replace(/^```\s*/, '').replace(/\s*```$/, '')
      }

      // Try to find JSON object if response contains extra text
      const jsonMatch = jsonText.match(/\{[\s\S]*?\}(?=\s*$|\s*```|\s*Note:|\s*$)/)
      if (jsonMatch) {
        jsonText = jsonMatch[0]
      }

      analysis = JSON.parse(jsonText)

      // Handle case where AI returns an array of threats - take the most severe one
      if (Array.isArray(analysis)) {
        const threats = analysis as any[]
        if (threats.length > 0) {
          // Sort by severity (Critical > High > Medium > Low)
          const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 }
          threats.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0))
          analysis = threats[0] as LlamaResponse
        } else {
          throw new Error("Empty threat array")
        }
      }

      // Validate required fields
      if (!analysis.threat_type || !analysis.severity || !analysis.summary) {
        throw new Error("Missing required fields in AI response")
      }

      // Ensure confidence is a number
      if (typeof analysis.confidence !== 'number') {
        analysis.confidence = parseInt(analysis.confidence) || 50
      }
    } catch (e) {
      console.error("⚠️ Invalid JSON:", e, "Response:", responseText)

      // Try to extract useful information from raw response as fallback
      const fallbackAnalysis = extractThreatFromRawText(responseText, logText)
      if (fallbackAnalysis) {
        analysis = fallbackAnalysis
      } else {
        analysis = {
          threat_type: "Analysis Error",
          severity: "Low",
          summary: "Could not parse AI output.",
          recommendation: "Review logs manually.",
          source_ip: "N/A",
          confidence: 0,
        }
      }
    }

    // ✅ Normalize severity capitalization
    const sev = analysis.severity.toLowerCase()
    const map: Record<string, LlamaResponse["severity"]> = {
      low: "Low",
      medium: "Medium",
      high: "High",
      critical: "Critical",
    }
    analysis.severity = map[sev] || "Low"

    // ✅ Save to Supabase
    const { data, error } = await supabase
      .from("analysis_results")
      .insert({
        user_id: session.user.id,
        threat_type: analysis.threat_type,
        severity: analysis.severity,
        summary: analysis.summary,
        recommendation: analysis.recommendation,
        source_ip: analysis.source_ip,
        confidence: analysis.confidence,
        log_content: logText,
      })
      .select()
      .single()

    if (error) {
      console.error("💾 Database error:", error)
      throw new Error("Failed to save analysis result")
    }

    // ✅ Analyze each log line
    const logLines = logText.split('\n').filter(line => line.trim())
    const lineAnalyses = await analyzeLogLines(logLines, data.id, supabase)
    
    console.log(`📊 Analyzed ${lineAnalyses.length} log lines, ${lineAnalyses.filter(l => l.threat_detected).length} threats detected`)

    // ✅ Send email if severity is High or Critical
    if (["High", "Critical"].includes(analysis.severity)) {
      try {
        await sendEmailAlert(session.user.email, analysis, data.id)
      } catch (err) {
        console.error("📧 Email sending failed:", err)
      }
    }

    return NextResponse.json({ analysisId: data.id, analysis })
  } catch (error: any) {
    console.error("🔥 Analysis error:", error)
    return NextResponse.json(
      { error: error.message || "Analysis failed" },
      { status: 500 }
    )
  }
}

/**
 * 📧 Email Alert Utility
 */
async function sendEmailAlert(
  email: string,
  analysis: LlamaResponse,
  analysisId: string
) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_SECURE === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  })

  const color = {
    Low: "#388e3c",
    Medium: "#fbc02d",
    High: "#f57c00",
    Critical: "#d32f2f",
  }[analysis.severity]

  const emoji =
    { Low: "🟢", Medium: "🟡", High: "🟠", Critical: "🔴" }[
      analysis.severity
    ] || "🔵"

  const appUrl = process.env.NEXT_PUBLIC_APP_URL || "https://your-app-url.com"
  const now = new Date().toLocaleString()
  const confidence =
    analysis.confidence !== undefined
      ? `<p><strong>Confidence:</strong> ${analysis.confidence}%</p>`
      : ""

  const html = `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:600px;margin:auto;">
    <h1 style="color:#1a237e;">🚨 SecuAI Alert</h1>
    <div style="background:#f5f5f5;padding:20px;border-radius:8px;">
      <h2>${analysis.threat_type}</h2>
      <span style="background:${color};color:#fff;padding:4px 10px;border-radius:8px;font-weight:bold;">
        ${emoji} ${analysis.severity}
      </span>
      ${confidence}
      <h3>🔍 Summary</h3><p>${analysis.summary}</p>
      <h3>🛡️ Source IP</h3><p>${analysis.source_ip || "N/A"}</p>
      <h3>✅ Recommendation</h3><p>${analysis.recommendation}</p>
      <div style="margin-top:20px;text-align:center;">
        <a href="${appUrl}/results/${analysisId}" style="
          background:#1a73e8;color:#fff;padding:10px 20px;
          text-decoration:none;border-radius:4px;">🔗 View Full Analysis</a>
      </div>
    </div>
    <p style="font-size:12px;color:#777;text-align:center;margin-top:15px;">
      Automated alert from SecuAI • ${now}
    </p>
  </div>`

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: `🚨 SecuAI Alert – ${analysis.threat_type} (${analysis.severity})`,
    html,
  })

  console.log(`📨 Alert sent to ${email}`)
}

async function analyzeLogLines(
  logLines: string[],
  analysisId: string,
  supabase: any
): Promise<LogLineAnalysis[]> {
  const analyses: LogLineAnalysis[] = []
  const threatPatterns = {
    bruteForce: /failed|failure|invalid|denied|authentication.*fail|login.*attempt/i,
    portScan: /port.*scan|nmap|masscan|connection.*refused|syn.*flood/i,
    malware: /malware|virus|trojan|ransomware|backdoor|cryptominer|botnet/i,
    sqlInjection: /union.*select|drop.*table|exec.*xp_|'.*or.*'.*=.*'|sleep\(|benchmark\(/i,
    xss: /<script|javascript:|onerror=|onload=|<iframe|eval\(|document\.cookie/i,
    privilegeEscalation: /sudo|root|privilege|escalat|admin.*access|setuid|chmod.*777/i,
    dataExfiltration: /exfiltrat|data.*transfer|unauthorized.*download|large.*upload|wget|curl.*http/i,
    suspiciousIP: /\b(?:10\.0\.0\.|192\.168\.|172\.16\.|127\.0\.0\.)/,
    ddos: /ddos|denial.*service|flood|amplification|slowloris/i,
    commandInjection: /;.*ls|;.*cat|;.*rm|&&.*whoami|\|.*nc|\$\(.*\)/i,
    pathTraversal: /\.\.\/|\.\.\\|%2e%2e|directory.*traversal/i,
    cryptoMining: /stratum|mining.*pool|xmrig|coinhive|cryptonight/i,
    webShell: /c99|r57|b374k|webshell|shell_exec|system\(/i,
    lateralMovement: /psexec|wmic|smbexec|lateral.*movement|pass.*the.*hash/i,
    reconnaissance: /whois|nslookup|dig|traceroute|enum|recon|fingerprint/i,
  }

  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
  const timestampRegex = /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/
  const portRegex = /(?:port|:)(\d{1,5})\b/i
  const httpMethodRegex = /\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/
  const statusCodeRegex = /\b(1\d{2}|2\d{2}|3\d{2}|4\d{2}|5\d{2})\b/
  const cveRegex = /CVE-\d{4}-\d{4,7}/gi

  const useCloudAI = process.env.USE_OPENROUTER === "true"
  const aiEndpoint = useCloudAI
    ? "https://openrouter.ai/api/v1/chat/completions"
    : "http://localhost:11434/api/generate"
  const aiModel = process.env.OPENROUTER_MODEL || "meta-llama/llama-3-8b-instruct"

  for (let i = 0; i < logLines.length; i++) {
    const line = logLines[i]
    const lineAnalysis: LogLineAnalysis = {
      line_number: i + 1,
      line_content: line,
      threat_detected: false,
      threat_indicators: [],
      recommended_actions: [],
      related_cves: [],
    }

    const ips = line.match(ipRegex)
    if (ips && ips.length > 0) {
      lineAnalysis.source_ip = ips[0]
      lineAnalysis.is_internal_ip = isInternalIP(ips[0])
      lineAnalysis.reputation_score = calculateIPReputation(ips[0])
      if (ips.length > 1) lineAnalysis.destination_ip = ips[1]
    }

    const timestamp = line.match(timestampRegex)
    if (timestamp) {
      lineAnalysis.timestamp = timestamp[0]
    }

    const portMatch = line.match(portRegex)
    if (portMatch) {
      lineAnalysis.port = parseInt(portMatch[1])
    }

    const httpMethod = line.match(httpMethodRegex)
    if (httpMethod) {
      lineAnalysis.http_method = httpMethod[0]
    }

    const statusCode = line.match(statusCodeRegex)
    if (statusCode) {
      lineAnalysis.status_code = parseInt(statusCode[0])
    }

    const cves = line.match(cveRegex)
    if (cves) {
      lineAnalysis.related_cves = cves
    }

    let maxScore = 0
    let detectedPattern = ""
    let detectedThreat = ""
    let severity: "Low" | "Medium" | "High" | "Critical" = "Low"
    const matchedPatterns: string[] = []

    for (const [threatName, pattern] of Object.entries(threatPatterns)) {
      if (pattern.test(line)) {
        lineAnalysis.threat_detected = true
        matchedPatterns.push(threatName)
        const score = calculateAnomalyScore(line, threatName)
        
        if (score > maxScore) {
          maxScore = score
          detectedPattern = threatName
          detectedThreat = formatThreatName(threatName)
          severity = getSeverityFromScore(score)
        }
      }
    }

    if (lineAnalysis.threat_detected) {
      lineAnalysis.anomaly_score = maxScore
      lineAnalysis.pattern_matched = detectedPattern
      lineAnalysis.threat_type = detectedThreat
      lineAnalysis.severity = severity
      lineAnalysis.attack_stage = determineAttackStage(detectedPattern)
      lineAnalysis.confidence_score = calculateConfidenceScore(line, matchedPatterns)
      lineAnalysis.threat_indicators = extractThreatIndicators(line, matchedPatterns)
      lineAnalysis.recommended_actions = getRecommendedActions(detectedPattern, severity)

      if (severity === "High" || severity === "Critical") {
        try {
          const aiAnalysis = await getAILineAnalysis(line, detectedThreat, aiEndpoint, aiModel)
          lineAnalysis.ai_explanation = aiAnalysis.explanation
          if (aiAnalysis.cves) {
            lineAnalysis.related_cves = [...(lineAnalysis.related_cves || []), ...aiAnalysis.cves]
          }
          if (aiAnalysis.indicators) {
            lineAnalysis.threat_indicators = [...(lineAnalysis.threat_indicators || []), ...aiAnalysis.indicators]
          }
        } catch (err) {
          console.error(`AI analysis failed for line ${i + 1}:`, err)
        }
      }
    }

    analyses.push(lineAnalysis)

    const insertData: any = {
      analysis_id: analysisId,
      line_number: lineAnalysis.line_number,
      line_content: lineAnalysis.line_content,
      threat_detected: lineAnalysis.threat_detected,
      threat_type: lineAnalysis.threat_type,
      severity: lineAnalysis.severity,
      anomaly_score: lineAnalysis.anomaly_score,
      pattern_matched: lineAnalysis.pattern_matched,
      source_ip: lineAnalysis.source_ip,
      destination_ip: lineAnalysis.destination_ip,
      timestamp: lineAnalysis.timestamp,
      ai_analysis: {
        ai_explanation: lineAnalysis.ai_explanation,
        threat_indicators: lineAnalysis.threat_indicators,
        recommended_actions: lineAnalysis.recommended_actions,
        related_cves: lineAnalysis.related_cves,
        attack_stage: lineAnalysis.attack_stage,
        confidence_score: lineAnalysis.confidence_score,
        port: lineAnalysis.port,
        http_method: lineAnalysis.http_method,
        status_code: lineAnalysis.status_code,
        is_internal_ip: lineAnalysis.is_internal_ip,
        reputation_score: lineAnalysis.reputation_score,
      }
    }

    const { error: insertError } = await supabase.from("log_lines").insert(insertData)
    if (insertError) {
      console.error(`Failed to insert line ${lineAnalysis.line_number}:`, insertError)
    }
  }

  return analyses
}

function calculateAnomalyScore(line: string, threatType: string): number {
  const baseScores: Record<string, number> = {
    bruteForce: 65,
    portScan: 70,
    malware: 95,
    sqlInjection: 90,
    xss: 85,
    privilegeEscalation: 92,
    dataExfiltration: 88,
    suspiciousIP: 50,
  }

  let score = baseScores[threatType] || 50

  if (line.toLowerCase().includes("critical")) score += 10
  if (line.toLowerCase().includes("alert")) score += 5
  if (line.toLowerCase().includes("error")) score += 3
  if ((line.match(/failed/gi) || []).length > 2) score += 10

  return Math.min(score, 100)
}

function getSeverityFromScore(score: number): "Low" | "Medium" | "High" | "Critical" {
  if (score >= 90) return "Critical"
  if (score >= 75) return "High"
  if (score >= 50) return "Medium"
  return "Low"
}

function formatThreatName(pattern: string): string {
  const names: Record<string, string> = {
    bruteForce: "Brute Force Attack",
    portScan: "Port Scanning",
    malware: "Malware Detection",
    sqlInjection: "SQL Injection",
    xss: "Cross-Site Scripting",
    privilegeEscalation: "Privilege Escalation",
    dataExfiltration: "Data Exfiltration",
    suspiciousIP: "Suspicious IP Activity",
    ddos: "DDoS Attack",
    commandInjection: "Command Injection",
    pathTraversal: "Path Traversal",
    cryptoMining: "Cryptocurrency Mining",
    webShell: "Web Shell",
    lateralMovement: "Lateral Movement",
    reconnaissance: "Reconnaissance",
  }
  return names[pattern] || "Unknown Threat"
}

function isInternalIP(ip: string): boolean {
  const parts = ip.split('.').map(Number)
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127
  )
}

function extractThreatFromRawText(aiResponse: string, originalLogs: string): LlamaResponse | null {
  try {
    const response = aiResponse.toLowerCase()

    // Extract threat type
    let threat_type = "Other"
    if (response.includes('brute force')) threat_type = "Brute Force"
    else if (response.includes('privilege escalation')) threat_type = "Privilege Escalation"
    else if (response.includes('port scan')) threat_type = "Port Scan"
    else if (response.includes('malware')) threat_type = "Malware Communication"
    else if (response.includes('data exfiltration') || response.includes('data transfer')) threat_type = "Data Exfiltration"
    else if (response.includes('unauthorized')) threat_type = "Unauthorized Access"
    else if (response.includes('sql injection')) threat_type = "SQL Injection"
    else if (response.includes('xss') || response.includes('cross-site')) threat_type = "Cross-Site Scripting"

    // Extract severity
    let severity: "Low" | "Medium" | "High" | "Critical" = "Medium"
    if (response.includes('critical')) severity = "Critical"
    else if (response.includes('high')) severity = "High"
    else if (response.includes('low')) severity = "Low"

    // Extract IP from response or logs
    let source_ip = "N/A"
    const ipMatch = aiResponse.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
    if (ipMatch) {
      source_ip = ipMatch[0]
    }

    // Generate summary from response
    let summary = "Potential security threat detected in logs."
    const summaryMatch = aiResponse.match(/(?:summary|threat|detected)[:\s]*([^.\n]+)/i)
    if (summaryMatch) {
      summary = summaryMatch[1].trim()
    }

    // Generate actionable recommendations based on threat type
    const recommendations: Record<string, string> = {
      "Brute Force": "1. Enable account lockout after failed attempts\n2. Implement rate limiting on authentication endpoints\n3. Use strong passwords and multi-factor authentication\n4. Monitor for suspicious login patterns",
      "Privilege Escalation": "1. Review and restrict sudo privileges\n2. Implement principle of least privilege\n3. Monitor for unusual privilege changes\n4. Audit user access logs regularly",
      "Port Scan": "1. Configure firewall to block suspicious scanning\n2. Implement rate limiting on network ports\n3. Use intrusion detection systems\n4. Monitor network traffic patterns",
      "Malware Communication": "1. Isolate affected systems immediately\n2. Run full malware scan\n3. Update antivirus signatures\n4. Block suspicious outbound connections",
      "Data Exfiltration": "1. Audit data access logs\n2. Implement data loss prevention (DLP)\n3. Restrict outbound data transfers\n4. Encrypt sensitive data at rest and in transit",
      "Unauthorized Access": "1. Review access control policies\n2. Implement proper authentication\n3. Monitor for anomalous access patterns\n4. Conduct security audit",
      "SQL Injection": "1. Use prepared statements and parameterized queries\n2. Implement input validation and sanitization\n3. Use web application firewall (WAF)\n4. Regular security code reviews",
      "Cross-Site Scripting": "1. Implement proper input validation\n2. Use Content Security Policy (CSP)\n3. Sanitize user inputs\n4. Regular security testing"
    }

    const recommendation = recommendations[threat_type] || "1. Review security logs\n2. Implement monitoring and alerting\n3. Conduct security assessment\n4. Update security policies"

    // Estimate confidence based on keywords
    let confidence = 50
    if (response.includes('high confidence') || response.includes('certain')) confidence = 80
    if (response.includes('critical') || response.includes('severe')) confidence = 90

    return {
      threat_type,
      severity,
      summary,
      source_ip,
      recommendation,
      confidence
    }
  } catch (e) {
    console.error("Fallback parsing failed:", e)
    return null
  }
}

function calculateIPReputation(ip: string): number {
  if (isInternalIP(ip)) return 100

  const suspiciousRanges = [
    { start: '1.0.0.0', end: '1.255.255.255', score: 60 },
    { start: '5.0.0.0', end: '5.255.255.255', score: 50 },
  ]
  
  return 75
}

function determineAttackStage(pattern: string): string {
  const stages: Record<string, string> = {
    reconnaissance: "Reconnaissance",
    portScan: "Reconnaissance",
    bruteForce: "Initial Access",
    sqlInjection: "Exploitation",
    xss: "Exploitation",
    commandInjection: "Exploitation",
    pathTraversal: "Exploitation",
    webShell: "Persistence",
    privilegeEscalation: "Privilege Escalation",
    lateralMovement: "Lateral Movement",
    dataExfiltration: "Exfiltration",
    malware: "Execution",
    cryptoMining: "Impact",
    ddos: "Impact",
  }
  return stages[pattern] || "Unknown"
}

function calculateConfidenceScore(line: string, patterns: string[]): number {
  let confidence = 50
  
  confidence += patterns.length * 15
  
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(line)) confidence += 10
  if (/\d{4}-\d{2}-\d{2}/.test(line)) confidence += 5
  if (/(error|critical|alert|warning)/i.test(line)) confidence += 10
  if (patterns.length > 2) confidence += 10
  
  return Math.min(confidence, 100)
}

function extractThreatIndicators(line: string, patterns: string[]): string[] {
  const indicators: string[] = []
  
  const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)
  if (ipMatch) indicators.push(`Suspicious IP: ${ipMatch[0]}`)
  
  const portMatch = line.match(/port[:\s]+(\d+)/i)
  if (portMatch) indicators.push(`Port: ${portMatch[1]}`)
  
  if (/failed|failure|denied/i.test(line)) {
    indicators.push("Failed authentication attempt")
  }
  
  if (/(union|select|drop|exec)/i.test(line)) {
    indicators.push("SQL injection pattern detected")
  }
  
  if (/<script|javascript:/i.test(line)) {
    indicators.push("XSS payload detected")
  }
  
  if (/sudo|root|admin/i.test(line)) {
    indicators.push("Privilege escalation attempt")
  }
  
  const cveMatch = line.match(/CVE-\d{4}-\d{4,7}/gi)
  if (cveMatch) {
    indicators.push(`CVE Reference: ${cveMatch.join(', ')}`)
  }
  
  return indicators
}

function getRecommendedActions(pattern: string, severity: string): string[] {
  const actions: Record<string, string[]> = {
    bruteForce: [
      "Block source IP immediately",
      "Enable account lockout policies",
      "Implement rate limiting",
      "Review authentication logs",
      "Enable MFA for affected accounts"
    ],
    portScan: [
      "Block scanning IP at firewall",
      "Review firewall rules",
      "Enable intrusion detection",
      "Monitor for follow-up attacks"
    ],
    malware: [
      "Isolate affected system immediately",
      "Run full antivirus scan",
      "Check for persistence mechanisms",
      "Review network connections",
      "Restore from clean backup if needed"
    ],
    sqlInjection: [
      "Block malicious requests",
      "Patch vulnerable application",
      "Use parameterized queries",
      "Review database logs",
      "Implement WAF rules"
    ],
    xss: [
      "Sanitize user inputs",
      "Implement Content Security Policy",
      "Review affected pages",
      "Update security headers"
    ],
    privilegeEscalation: [
      "Revoke elevated privileges",
      "Audit user permissions",
      "Review sudo/admin logs",
      "Implement least privilege principle",
      "Monitor for lateral movement"
    ],
    dataExfiltration: [
      "Block outbound connections",
      "Identify compromised data",
      "Review DLP policies",
      "Investigate data access logs",
      "Notify affected parties if needed"
    ],
    ddos: [
      "Enable DDoS mitigation",
      "Contact ISP/CDN provider",
      "Implement rate limiting",
      "Scale infrastructure if possible"
    ],
    commandInjection: [
      "Patch vulnerable application",
      "Sanitize command inputs",
      "Review system logs",
      "Check for backdoors"
    ],
    webShell: [
      "Remove web shell immediately",
      "Scan for additional backdoors",
      "Review web server logs",
      "Patch vulnerable application",
      "Restore from clean backup"
    ],
  }
  
  return actions[pattern] || ["Investigate further", "Monitor for additional activity", "Review security logs"]
}

async function getAILineAnalysis(
  line: string,
  threatType: string,
  aiEndpoint: string,
  aiModel: string
): Promise<{ explanation: string; cves?: string[]; indicators?: string[] }> {
  const prompt = `Analyze this security log line for ${threatType}:

"${line}"

Provide a detailed analysis in JSON format:
{
  "explanation": "Brief technical explanation of the threat",
  "cves": ["CVE-XXXX-XXXX if applicable"],
  "indicators": ["specific threat indicators found"]
}

Keep response concise and technical.`

  const response = await fetch(aiEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
    },
    body: JSON.stringify({
      model: aiModel,
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity expert. Respond only in valid JSON."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      temperature: 0.1,
      max_tokens: 300,
    }),
  })

  if (!response.ok) {
    throw new Error("AI analysis request failed")
  }

  const data = await response.json()
  const content = data?.choices?.[0]?.message?.content || "{}"
  
  try {
    return JSON.parse(content)
  } catch {
    return {
      explanation: "AI analysis unavailable",
      cves: [],
      indicators: []
    }
  }
}
