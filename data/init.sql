-- DragonShard Database Initialization Script
-- This script is executed when the PostgreSQL container starts for the first time

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone
SET timezone = 'UTC';

-- Create additional databases if needed
-- CREATE DATABASE dragonshard_test;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE dragonshard TO dragonshard;
GRANT ALL PRIVILEGES ON SCHEMA public TO dragonshard;

-- Create indexes for better performance (will be created by SQLAlchemy, but good to have)
-- These will be created automatically by SQLAlchemy, but we can add custom indexes here if needed

-- Set up connection limits and other PostgreSQL settings
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Reload configuration
SELECT pg_reload_conf();

-- Create a function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_used = EXTRACT(EPOCH FROM NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'DragonShard database initialized successfully';
END $$; 