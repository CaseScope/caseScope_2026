"""
OpenSearch Client Utility
Shared factory function for creating OpenSearch connections
"""

from opensearchpy import OpenSearch
import logging

logger = logging.getLogger(__name__)


def get_opensearch_client(config=None):
    """
    Create and return an OpenSearch client instance
    
    Args:
        config: Optional config object. If not provided, imports from app.config
    
    Returns:
        OpenSearch: Configured OpenSearch client
    """
    if config is None:
        try:
            from app.config import Config
            config = Config
        except ImportError:
            from config import Config
            config = Config
    
    try:
        client = OpenSearch(
            hosts=[{
                'host': config.OPENSEARCH_HOST,
                'port': config.OPENSEARCH_PORT
            }],
            use_ssl=config.OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30
        )
        return client
    except Exception as e:
        logger.error(f"Failed to create OpenSearch client: {e}")
        raise

