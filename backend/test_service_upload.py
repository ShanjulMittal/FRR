#!/usr/bin/env python3
"""
Test script to upload observations.csv with proper service column mapping
"""

import requests
import json
import os

def test_upload_with_service_mapping():
    """Test uploading observations.csv with service column mapping"""
    
    url = "http://localhost:5000/api/upload"
    file_path = "/Users/shanjulmittal/FRR/test-files/observations.csv"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return False
    
    # Proper column mapping for the Service column
    column_mapping = {
        "Service": "service"
    }
    
    print(f"Uploading {file_path} with column mapping: {column_mapping}")
    
    with open(file_path, 'rb') as f:
        files = {
            'file': f
        }
        data = {
            'file_type': 'firewall',
            'column_mapping': json.dumps(column_mapping)
        }
        
        try:
            response = requests.post(url, files=files, data=data)
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Success: {result}")
                return True
            else:
                print(f"Error: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return False

if __name__ == "__main__":
    success = test_upload_with_service_mapping()
    if success:
        print("\n✅ Upload with service mapping completed successfully!")
        print("The Service column should now be properly mapped and parsed.")
    else:
        print("\n❌ Upload failed!")
        print("Please check if the Flask server is running on localhost:5000")