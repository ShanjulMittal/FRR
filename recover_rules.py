import re
import sqlite3
from datetime import datetime

# Connect to DB
conn = sqlite3.connect('./backend/firewall_review.db')
cursor = conn.cursor()

# Read dump
with open('strings_dump.txt', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Define patterns
fields = r'(source_ip|dest_ip|action|service_port|service_protocol|rule_name|hit_count|service_count|application_name|custom_service_count)'
operators = r'(equals|not_equals|regex_match|not_regex_match|contains|not_contains|range|not_range|greater_than|less_than|cmdb_category_violation)'
severities = r'(High|Medium|Low|Critical)'
templates = r'(PCI DSS 4.0.1 Template|ISO 27001 Template|PCI-DSS 4.0.1 Template|ISO 27001 Baseline)'

# Regex for PCI/ISO rules
# Note: logic field might be skipped if NULL
regex = re.compile(
    r'(?P<rule_name>(?:PCI|ISO)-[^\n]+?)'
    r'(?P<description>[A-Z][a-zA-Z0-9\s\-\(\)\.,]+?)'
    r'(?P<field>' + fields + r')'
    r'(?P<operator>' + operators + r')'
    r'(?P<value>.+?)'
    r'(?P<severity>' + severities + r')'
    r'(?P<created_by>' + templates + r')'
    r'(?P<created_at>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)'
    r'(?P<updated_at>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)'
)

matches = []
# Find all matches
# We iterate to find all non-overlapping matches
pos = 0
while True:
    m = regex.search(content, pos)
    if not m:
        break
    matches.append(m.groupdict())
    pos = m.end()

print(f"Found {len(matches)} rules")

# Insert into DB
inserted = 0
for m in matches:
    # Check if exists
    cursor.execute("SELECT id FROM compliance_rules WHERE rule_name = ?", (m['rule_name'],))
    if cursor.fetchone():
        print(f"Skipping existing: {m['rule_name']}")
        continue
        
    print(f"Restoring: {m['rule_name']}")
    try:
        cursor.execute("""
            INSERT INTO compliance_rules 
            (rule_name, description, field_to_check, operator, value, severity, created_by, created_at, updated_at, is_active, logic)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            m['rule_name'],
            m['description'],
            m['field'],
            m['operator'],
            m['value'],
            m['severity'],
            m['created_by'],
            m['created_at'],
            m['updated_at'],
            True, # is_active
            None  # logic (assuming NULL for these basic rules)
        ))
        inserted += 1
    except Exception as e:
        print(f"Error inserting {m['rule_name']}: {e}")

conn.commit()
print(f"Successfully restored {inserted} rules")
conn.close()
