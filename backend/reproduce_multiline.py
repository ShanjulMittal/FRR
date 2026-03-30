import requests
import json

url = 'http://localhost:5001/api/object-groups/import'

# Simulate CSV with quoted multiline values (common for 'members')
# And a comment line to ensure filtering is tested
file_content = """# This is a comment
Name,Addresses
TestGroup_Single,10.0.0.1
TestGroup_Multi,"10.0.0.2
10.0.0.3"
"""

files = {
    'file': ('DRPA-Address Group.csv', file_content, 'text/csv')
}

# Frontend mapping: CSV Header -> Internal Field
mapping = {
    "Name": ["name"],
    "Addresses": ["members"]
}

data = {
    'mapping': json.dumps(mapping)
}

print(f"Sending request to {url}")
try:
    response = requests.post(url, files=files, data=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
