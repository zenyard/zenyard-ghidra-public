#!/bin/bash
# Script to fix the Section.getClass() method name conflict in generated Java code
# This renames getClass() to getClassValue() to avoid conflict with Object.getClass()
#
# The OpenAPI generator creates a getClass() method for the "class" field in Section,
# which conflicts with Object.getClass(). This script renames it to getClassValue().

set -e

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECTION_FILE="$PROJECT_ROOT/build/generated/src/main/java/com/zenyard/decompai/ghidra/api/generated/model/Section.java"

if [ ! -f "$SECTION_FILE" ]; then
    echo "Warning: $SECTION_FILE not found. Skipping Section.getClass() fix."
    exit 0
fi

echo "Fixing Section.getClass() method name conflict in generated code..."

# Create a temporary file for the fixed content
TEMP_FILE=$(mktemp)

# Use a Python script embedded in bash for reliable text processing
python3 << PYTHON_SCRIPT
import sys
import re

input_file = "$SECTION_FILE"
output_file = "$TEMP_FILE"

with open(input_file, 'r') as f:
    content = f.read()

# Step 1: Rename the method declaration
content = re.sub(r'public ClassEnum getClass\(\)', 'public ClassEnum getClassValue()', content)

# Step 2: Fix equals() method - ensure Object.getClass() uses 'this.getClass()'
# Pattern: "if (o == null || getClass() != o.getClass())" -> "if (o == null || this.getClass() != o.getClass())"
content = re.sub(
    r'if \(o == null \|\| getClass\(\) != o\.getClass\(\)',
    'if (o == null || this.getClass() != o.getClass()',
    content
)

# Step 3: Replace standalone getClass() calls (not preceded by a dot or word character)
# This catches getClass() in method bodies, but preserves this.getClass() and o.getClass()
# We use negative lookbehind to ensure we don't match after a dot or word char
content = re.sub(r'(?<!\.)(?<!\w)getClass\(\)', 'getClassValue()', content)

# Step 4: Restore Object.getClass() calls that were incorrectly replaced
# Restore this.getClass() and variable.getClass() patterns
content = re.sub(r'this\.getClassValue\(\)', 'this.getClass()', content)
content = re.sub(r'(\w+)\.getClassValue\(\)', r'\1.getClass()', content)

with open(output_file, 'w') as f:
    f.write(content)
PYTHON_SCRIPT

# If Python failed, fall back to a simpler sed approach
if [ ! -s "$TEMP_FILE" ]; then
    echo "Python script failed, using sed fallback..."
    cp "$SECTION_FILE" "$TEMP_FILE"
    
    # Determine sed command based on OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        SED_CMD="sed -i ''"
    else
        SED_CMD="sed -i"
    fi
    
    # Rename method declaration
    $SED_CMD 's/public ClassEnum getClass()/public ClassEnum getClassValue()/g' "$TEMP_FILE"
    
    # Fix equals() method
    $SED_CMD 's/if (o == null || getClass() != o\.getClass()/if (o == null || this.getClass() != o.getClass()/g' "$TEMP_FILE"
    
    # Replace standalone getClass() - match getClass() not preceded by word char or dot
    # This is a simplified version that should work for most cases
    $SED_CMD 's/\([^a-zA-Z0-9_.]\)getClass()/\1getClassValue()/g' "$TEMP_FILE"
    
    # Restore Object.getClass() calls
    $SED_CMD 's/this\.getClassValue()/this.getClass()/g' "$TEMP_FILE"
    $SED_CMD 's/\([a-zA-Z0-9_]\+\)\.getClassValue()/\1.getClass()/g' "$TEMP_FILE"
fi

# Replace the original file
mv "$TEMP_FILE" "$SECTION_FILE"

echo "✓ Fixed Section.getClass() → getClassValue() in $SECTION_FILE"
