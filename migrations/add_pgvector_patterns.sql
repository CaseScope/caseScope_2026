-- Create pattern_embeddings table for vector storage
-- Using pgvector for semantic search

-- Enable pgvector if not already enabled
CREATE EXTENSION IF NOT EXISTS vector;

-- Create table for pattern embeddings
CREATE TABLE IF NOT EXISTS pattern_embeddings (
    id SERIAL PRIMARY KEY,
    pattern_id VARCHAR(200) UNIQUE NOT NULL,  -- e.g., "sigma_process_creation_susp_cmd"
    source VARCHAR(50) NOT NULL,              -- 'sigma' or 'mitre'
    content TEXT NOT NULL,                    -- Full text content for display
    embedding vector(384) NOT NULL,           -- 384 dimensions for BAAI/bge-small-en-v1.5
    
    -- Metadata (JSON for flexibility)
    metadata JSONB,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes
    CONSTRAINT pattern_embeddings_source_check CHECK (source IN ('sigma', 'mitre'))
);

-- Create index for vector similarity search (HNSW for speed)
CREATE INDEX IF NOT EXISTS pattern_embeddings_embedding_idx 
    ON pattern_embeddings 
    USING hnsw (embedding vector_cosine_ops);

-- Create index for source filtering
CREATE INDEX IF NOT EXISTS pattern_embeddings_source_idx 
    ON pattern_embeddings (source);

-- Create GIN index for metadata JSONB queries
CREATE INDEX IF NOT EXISTS pattern_embeddings_metadata_idx 
    ON pattern_embeddings 
    USING gin (metadata);

-- Grant permissions to casescope user
GRANT ALL ON pattern_embeddings TO casescope;
GRANT USAGE, SELECT ON SEQUENCE pattern_embeddings_id_seq TO casescope;

-- Show table info
\d pattern_embeddings

