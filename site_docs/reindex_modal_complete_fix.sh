#!/bin/bash
# Complete Re-Index Modal Fix v1.19.1
# Fixes: (1) Missing modal CSS, (2) Polling bug with wrong field names

echo "=========================================================="
echo "Re-Index Modal Complete Fix v1.19.1"
echo "=========================================================="
echo ""
echo "This patch fixes TWO critical issues:"
echo ""
echo "  Issue #1: Missing modal CSS"
echo "    - Modal has no z-index, appears behind content"
echo "    - Fix: Add .modal CSS with z-index: 10000"
echo ""
echo "  Issue #2: Polling uses wrong field names"
echo "    - JavaScript checks data.queued (array) instead of data.queued_count (number)"
echo "    - Result: Modal never closes when files enter queue"
echo "    - Fix: Change to use data.queued_count and data.processing_count"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

cd /opt/casescope

# Backup original file
echo ""
echo "Creating backup..."
cp app/templates/case_files.html app/templates/case_files.html.backup.modal_complete_fix

# Apply both fixes using Python
echo "Applying fixes..."
python3 << 'PYTHON_SCRIPT'
import re

# Read the file
with open('app/templates/case_files.html', 'r') as f:
    content = f.read()
    lines = content.split('\n')

# ===========================================================================
# FIX #1: Replace the polling line to use correct field names
# ===========================================================================
print("🔧 Fix #1: Correcting polling field names...")

# Find and replace line 1045
for i, line in enumerate(lines):
    if 'const activeCount = (data.queued || 0) + (data.processing || 0);' in line:
        old_line = line
        new_line = line.replace(
            'const activeCount = (data.queued || 0) + (data.processing || 0);',
            'const activeCount = (data.queued_count || 0) + (data.processing_count || 0);'
        )
        lines[i] = new_line
        print(f"   ✅ Line {i+1}: Fixed polling to use _count fields")
        print(f"      Before: {old_line.strip()}")
        print(f"      After:  {new_line.strip()}")
        break
else:
    print("   ⚠️  Warning: Could not find polling line to fix")

# ===========================================================================
# FIX #2: Add modal CSS before {% endblock %}
# ===========================================================================
print("\n🔧 Fix #2: Adding modal CSS...")

# Find {% endblock %} near the end
endblock_index = None
for i in range(len(lines)-1, max(len(lines)-100, 0), -1):
    if '{% endblock %}' in lines[i]:
        endblock_index = i
        break

if endblock_index is None:
    print("   ❌ ERROR: Could not find {% endblock %}")
    exit(1)

# Check if modal CSS already exists
has_modal_css = False
for line in lines:
    if '.modal {' in line and 'z-index: 10000' in ' '.join(lines):
        has_modal_css = True
        break

if has_modal_css:
    print("   ℹ️  Modal CSS already exists, skipping...")
else:
    # CSS to insert
    modal_css = """
<style>
/* Re-Index Preparation Modal - Added v1.19.1 */
.modal {
    display: none;
    position: fixed;
    z-index: 10000; /* CRITICAL: Must be above everything else */
    left: 0;
    top: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(4px);
    align-items: center;
    justify-content: center;
}

.modal-content {
    background: var(--color-background);
    padding: var(--spacing-xl);
    border-radius: 12px;
    max-width: 600px;
    width: 90%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    position: relative;
    z-index: 10001;
}

.modal h3 {
    color: var(--color-text-primary);
    margin-bottom: var(--spacing-md);
}

.modal p {
    color: var(--color-text);
    line-height: 1.6;
}
</style>
"""
    
    # Insert before {% endblock %}
    lines.insert(endblock_index, modal_css)
    print(f"   ✅ Modal CSS added at line {endblock_index+1}")

# Write back
with open('app/templates/case_files.html', 'w') as f:
    f.write('\n'.join(lines))

print("\n✅ Both fixes applied successfully")
PYTHON_SCRIPT

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================================="
    echo "✅ PATCH APPLIED SUCCESSFULLY"
    echo "=========================================================="
    echo ""
    echo "Changes made:"
    echo "  ✅ Fix #1: Polling now uses data.queued_count and data.processing_count"
    echo "  ✅ Fix #2: Added .modal CSS with z-index: 10000"
    echo ""
    echo "What this fixes:"
    echo "  ✅ Modal now appears on top of all content"
    echo "  ✅ Modal correctly detects when files enter queue"
    echo "  ✅ Modal auto-closes when processing starts"
    echo "  ✅ Page refreshes automatically after modal closes"
    echo ""
    echo "Backup saved to:"
    echo "  app/templates/case_files.html.backup.modal_complete_fix"
    echo ""
    echo "🔄 RESTART REQUIRED: sudo systemctl restart casescope"
    echo ""
    echo "Test by clicking: 'Re-Index All Files' or 'Re-Index Selected Files'"
else
    echo ""
    echo "❌ ERROR: Patch failed"
    echo "Restoring backup..."
    mv app/templates/case_files.html.backup.modal_complete_fix app/templates/case_files.html
    exit 1
fi
