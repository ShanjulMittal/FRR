#!/usr/bin/env python3
"""
Test script to verify that the frontend receives correct rule_text data
"""

import requests
import json

def test_frontend_api():
    """Test the API endpoint that the frontend uses"""
    try:
        # Test the API endpoint with the same parameters the frontend would use
        url = "http://localhost:5001/api/normalized-rules"
        params = {
            'per_page': 5,
            'is_deleted': 'false',
            'page': 1
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Response Status: {response.status_code}")
            print(f"✅ Total Rules: {data.get('total', 0)}")
            print(f"✅ Rules in Response: {len(data.get('normalized_rules', []))}")
            
            if data.get('normalized_rules'):
                print("\n📋 Sample Rules:")
                for i, rule in enumerate(data['normalized_rules'][:3]):
                    print(f"\nRule {i+1} (ID: {rule['id']}):")
                    print(f"  Rule Text: \"{rule.get('rule_text', 'N/A')}\"")
                    print(f"  Raw Text: \"{rule.get('raw_text', 'N/A')}\"")
                    print(f"  Action: {rule.get('action', 'N/A')}")
                    print(f"  Source: {rule.get('source_ip', 'N/A')}")
                    print(f"  Destination: {rule.get('dest_ip', 'N/A')}")
                    
                    # Check if rule_text is meaningful
                    rule_text = rule.get('rule_text', '')
                    if rule_text and rule_text not in ['-', '1', '2', '']:
                        print(f"  ✅ Rule text is meaningful")
                    else:
                        print(f"  ❌ Rule text is not meaningful: '{rule_text}'")
            else:
                print("❌ No rules found in response")
        else:
            print(f"❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error testing API: {str(e)}")

if __name__ == "__main__":
    test_frontend_api()