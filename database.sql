-- Create users table
CREATE TABLE IF NOT EXISTS users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  uid TEXT UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create access_keys table
CREATE TABLE IF NOT EXISTS access_keys (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  key_value TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active',
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create sessions table for serverless reliability
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  key TEXT NOT NULL,
  fingerprint TEXT,
  action TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- RLS POLICIES (Run these in Supabase SQL Editor)
-- Enable RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Sessions Policies
CREATE POLICY "Allow anon insert sessions" ON sessions FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon select sessions" ON sessions FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon delete sessions" ON sessions FOR DELETE TO anon USING (true);

-- Users Policies
CREATE POLICY "Allow anon insert users" ON users FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon select users" ON users FOR SELECT TO anon USING (true);

-- Access Keys Policies
CREATE POLICY "Allow anon select keys" ON access_keys FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon update keys" ON access_keys FOR UPDATE TO anon USING (true);