-- Create users table (handled by Supabase Auth)
-- Create logs table
CREATE TABLE IF NOT EXISTS logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  log_content TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create analysis_results table
CREATE TABLE IF NOT EXISTS analysis_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  threat_type VARCHAR(255) NOT NULL,
  severity VARCHAR(50) NOT NULL,
  summary TEXT NOT NULL,
  recommendation TEXT,
  source_ip VARCHAR(45),
  log_content TEXT,
  confidence INTEGER,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create log_lines table for line-by-line analysis
CREATE TABLE IF NOT EXISTS log_lines (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id UUID NOT NULL REFERENCES analysis_results(id) ON DELETE CASCADE,
  line_number INTEGER NOT NULL,
  line_content TEXT NOT NULL,
  threat_detected BOOLEAN DEFAULT false,
  threat_type VARCHAR(255),
  severity VARCHAR(50),
  anomaly_score DECIMAL(5,2),
  pattern_matched VARCHAR(255),
  source_ip VARCHAR(45),
  destination_ip VARCHAR(45),
  timestamp TIMESTAMP WITH TIME ZONE,
  ai_analysis JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  analysis_id UUID REFERENCES analysis_results(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Enable RLS
ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

-- RLS Policies for logs
CREATE POLICY "Users can view their own logs" ON logs FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own logs" ON logs FOR INSERT WITH CHECK (auth.uid() = user_id);

-- RLS Policies for analysis_results
CREATE POLICY "Users can view their own analysis" ON analysis_results FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own analysis" ON analysis_results FOR INSERT WITH CHECK (auth.uid() = user_id);

-- RLS Policies for log_lines
CREATE POLICY "Users can view log lines from their analysis" ON log_lines FOR SELECT 
  USING (EXISTS (SELECT 1 FROM analysis_results WHERE analysis_results.id = log_lines.analysis_id AND analysis_results.user_id = auth.uid()));
CREATE POLICY "System can insert log lines" ON log_lines FOR INSERT WITH CHECK (true);

-- RLS Policies for alerts
CREATE POLICY "Users can view their own alerts" ON alerts FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "System can insert alerts" ON alerts FOR INSERT WITH CHECK (true);

-- Create indexes for performance
CREATE INDEX idx_analysis_user_id ON analysis_results(user_id);
CREATE INDEX idx_analysis_created_at ON analysis_results(created_at DESC);
CREATE INDEX idx_log_lines_analysis_id ON log_lines(analysis_id);
CREATE INDEX idx_log_lines_threat_detected ON log_lines(threat_detected);
CREATE INDEX idx_log_lines_severity ON log_lines(severity);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
