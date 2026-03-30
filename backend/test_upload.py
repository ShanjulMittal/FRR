#!/usr/bin/env python3
import requests
import os

# Test uploading the observations.xlsx file to the API
def test_upload():
    url = "http://localhost:5001/api/analyze-file"
    file_path = "/Users/shanjulmittal/FRR/backend/sample_observations.xlsx"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {'file_type': 'firewall'}
        
        print(f"Uploading {file_path} to {url}")
        response = requests.post(url, files=files, data=data)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")

if __name__ == "__main__":
    test_upload()