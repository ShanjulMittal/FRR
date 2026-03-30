import requests
import json
import codecs

url = 'http://localhost:5001/api/object-groups/import'

# Simulate CSV with BOM
content = """Name,Addresses
TestGroup_BOM,10.0.0.1
"""
# Add BOM
file_content = codecs.BOM_UTF8 + content.encode('utf-8')

files = {
    'file': ('DRPA-Address Group-BOM.csv', file_content, 'text/csv')
}

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
