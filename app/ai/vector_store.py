"""
Vector store for attack patterns using PostgreSQL + pgvector
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
from fastembed import TextEmbedding
import psycopg2
from psycopg2.extras import execute_values
import numpy as np

logger = logging.getLogger(__name__)


class PatternStore:
    """
    Stores and retrieves attack patterns for RAG using PostgreSQL + pgvector
    """
    
    def __init__(self, db_config: Dict, embedding_model: str = "BAAI/bge-small-en-v1.5"):
        """
        Initialize pattern store with PostgreSQL connection
        
        Args:
            db_config: Dict with keys: host, port, database, user, password
            embedding_model: FastEmbed model name
        """
        self.db_config = db_config
        self.embedder = TextEmbedding(model_name=embedding_model)
        
        # Test connection
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM pattern_embeddings")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        
        logger.info(f"PatternStore initialized with {count} patterns in PostgreSQL")
    
    def _get_connection(self):
        """Get PostgreSQL connection"""
        return psycopg2.connect(
            host=self.db_config['host'],
            port=self.db_config['port'],
            database=self.db_config['database'],
            user=self.db_config['user'],
            password=self.db_config['password']
        )
    
    def _embed(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for texts"""
        return [list(embedding) for embedding in self.embedder.embed(texts)]
    
    def add_sigma_rules(self, rules_dir: str) -> int:
        """
        Ingest Sigma rules from directory
        
        Returns: Number of rules ingested
        """
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.error(f"Sigma rules directory not found: {rules_dir}")
            return 0
        
        records = []
        
        for yaml_file in rules_path.rglob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                if not rule or not isinstance(rule, dict):
                    continue
                
                # Build searchable text
                title = rule.get('title', '')
                description = rule.get('description', '')
                tags = rule.get('tags', [])
                level = rule.get('level', '')
                detection = yaml.dump(rule.get('detection', {}))
                
                # Format for embedding
                content = f"""
Title: {title}
Description: {description}
Level: {level}
Tags: {', '.join(tags) if tags else 'none'}
Detection Logic:
{detection}
""".strip()
                
                metadata = {
                    'title': title,
                    'level': level,
                    'tags': ','.join(tags) if tags else '',
                    'file': str(yaml_file.name)
                }
                
                pattern_id = f"sigma_{yaml_file.stem}"
                
                records.append({
                    'pattern_id': pattern_id,
                    'content': content,
                    'metadata': metadata
                })
                
            except Exception as e:
                logger.warning(f"Failed to parse {yaml_file}: {e}")
                continue
        
        if records:
            self._batch_insert(records, 'sigma')
            logger.info(f"Ingested {len(records)} Sigma rules")
        
        return len(records)
    
    def add_mitre_attack(self, json_path: str) -> int:
        """
        Ingest MITRE ATT&CK techniques
        
        Returns: Number of techniques ingested
        """
        if not os.path.exists(json_path):
            logger.error(f"MITRE ATT&CK file not found: {json_path}")
            return 0
        
        with open(json_path, 'r') as f:
            attack_data = json.load(f)
        
        records = []
        
        for obj in attack_data.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            
            technique_id = ''
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', '')
                    break
            
            if not technique_id:
                continue
            
            name = obj.get('name', '')
            description = obj.get('description', '')[:1000]  # Truncate
            tactics = [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])]
            
            content = f"""
MITRE ATT&CK Technique: {technique_id} - {name}
Tactics: {', '.join(tactics)}
Description: {description}
""".strip()
            
            metadata = {
                'technique_id': technique_id,
                'name': name,
                'tactics': ','.join(tactics)
            }
            
            pattern_id = f"mitre_{technique_id}"
            
            records.append({
                'pattern_id': pattern_id,
                'content': content,
                'metadata': metadata
            })
        
        if records:
            self._batch_insert(records, 'mitre')
            logger.info(f"Ingested {len(records)} MITRE techniques")
        
        return len(records)
    
    def _batch_insert(self, records: List[Dict], source: str, batch_size: int = 100):
        """
        Batch insert records with embeddings into PostgreSQL
        """
        conn = self._get_connection()
        cur = conn.cursor()
        
        # Process in batches
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            
            # Generate embeddings for batch
            contents = [r['content'] for r in batch]
            embeddings = self._embed(contents)
            
            # Prepare data for insertion
            values = []
            for record, embedding in zip(batch, embeddings):
                # Convert numpy float32 to Python float for psycopg2
                embedding_floats = [float(x) for x in embedding]
                
                values.append((
                    record['pattern_id'],
                    source,
                    record['content'],
                    embedding_floats,  # pgvector handles list -> vector conversion
                    json.dumps(record['metadata'])
                ))
            
            # Insert with ON CONFLICT DO NOTHING to avoid duplicates
            execute_values(
                cur,
                """
                INSERT INTO pattern_embeddings (pattern_id, source, content, embedding, metadata)
                VALUES %s
                ON CONFLICT (pattern_id) DO NOTHING
                """,
                values
            )
            
            conn.commit()
            logger.info(f"Inserted batch {i // batch_size + 1}: {len(batch)} patterns")
        
        cur.close()
        conn.close()
    
    def search(self, query: str, k: int = 5, source_filter: Optional[str] = None) -> List[Dict]:
        """
        Search for relevant patterns using cosine similarity
        
        Args:
            query: Search query
            k: Number of results
            source_filter: Optional filter ('sigma' or 'mitre')
        
        Returns: List of matching patterns with metadata
        """
        # Generate query embedding and convert to Python floats
        query_embedding = self._embed([query])[0]
        query_embedding = [float(x) for x in query_embedding]
        
        conn = self._get_connection()
        cur = conn.cursor()
        
        # Build SQL query
        sql = """
            SELECT 
                pattern_id,
                source,
                content,
                metadata,
                1 - (embedding <=> %s::vector) as similarity
            FROM pattern_embeddings
        """
        params = [query_embedding]
        
        if source_filter:
            sql += " WHERE source = %s"
            params.append(source_filter)
        
        sql += " ORDER BY embedding <=> %s::vector LIMIT %s"
        params.extend([query_embedding, k])
        
        cur.execute(sql, params)
        results = cur.fetchall()
        
        patterns = []
        for row in results:
            patterns.append({
                'id': row[0],
                'source': row[1],
                'content': row[2],
                'metadata': row[3],
                'score': float(row[4])
            })
        
        cur.close()
        conn.close()
        
        return patterns
    
    def get_stats(self) -> Dict:
        """Get collection statistics"""
        conn = self._get_connection()
        cur = conn.cursor()
        
        # Total patterns
        cur.execute("SELECT COUNT(*) FROM pattern_embeddings")
        total = cur.fetchone()[0]
        
        # By source
        cur.execute("""
            SELECT source, COUNT(*) 
            FROM pattern_embeddings 
            GROUP BY source
        """)
        by_source = dict(cur.fetchall())
        
        cur.close()
        conn.close()
        
        return {
            'total_patterns': total,
            'by_source': by_source
        }
