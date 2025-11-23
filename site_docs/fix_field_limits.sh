#!/bin/bash
# Fix forensic field indexing failures by increasing field limits
# v1.19.7 - Case 11 Fix

echo "==================================================================="
echo "Fixing OpenSearch Field Limit for Forensic Fields"
echo "==================================================================="

# Get all case indices
indices=$(curl -s 'http://localhost:9200/_cat/indices/case_*?h=index' | tr '\n' ' ')

if [ -z "$indices" ]; then
    echo "No case indices found"
    exit 0
fi

echo "Found indices: $indices"
echo

for index in $indices; do
    echo "Updating field limit for $index..."
    
    # Increase field limit from 10,000 to 50,000
    curl -X PUT "localhost:9200/$index/_settings" -H 'Content-Type: application/json' -d'
    {
      "index.mapping.total_fields.limit": 50000
    }
    '
    echo
    
    # Also increase nested fields limit
    curl -X PUT "localhost:9200/$index/_settings" -H 'Content-Type: application/json' -d'
    {
      "index.mapping.nested_fields.limit": 500
    }
    '
    echo
done

echo
echo "==================================================================="
echo "Field Limits Updated Successfully"
echo "- total_fields.limit: 10000 → 50000"
echo "- nested_fields.limit: 100 → 500"
echo "==================================================================="

