-- Add ActiveTask table for task persistence
-- Allows users to reconnect to running tasks after page refresh

CREATE TABLE IF NOT EXISTS active_tasks (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
    task_type VARCHAR(50) NOT NULL,
    task_id VARCHAR(255) NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'running' NOT NULL,
    progress_percent INTEGER DEFAULT 0,
    progress_message VARCHAR(500),
    
    -- Timing
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    
    -- Results
    result_data JSONB,
    error_message TEXT
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_active_tasks_case_id ON active_tasks(case_id);
CREATE INDEX IF NOT EXISTS idx_active_tasks_task_type ON active_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_active_tasks_task_id ON active_tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_active_tasks_user_id ON active_tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_active_tasks_status ON active_tasks(status);
CREATE INDEX IF NOT EXISTS idx_active_tasks_started_at ON active_tasks(started_at);

-- Composite index for common query pattern (case + type + status)
CREATE INDEX IF NOT EXISTS idx_active_tasks_case_type_status 
ON active_tasks(case_id, task_type, status);

-- Clean up old completed tasks (optional - run manually or via cron)
-- DELETE FROM active_tasks WHERE status IN ('completed', 'failed', 'cancelled') AND completed_at < NOW() - INTERVAL '7 days';

