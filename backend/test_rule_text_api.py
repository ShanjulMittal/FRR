#!/usr/bin/env python3
"""
Test script to verify rule_text vs raw_text field mapping
"""

import requests
import json

def test_api_response():
    """Test that the API returns both rule_text and raw_text fields"""
    try:
        # Test the normalized rules API
        response = requests.get('http://localhost:5001/api/normalized-rules?per_page=5')
        
        if response.status_code != 200:
            print(f"API request failed with status: {response.status_code}")
            return
        
        data = response.json()
        rules = data.get('rules', [])
        
        if not rules:
            print("No rules found in the response")
            return
        
        print(f"Found {len(rules)} rules. Testing first rule:")
        print("-" * 50)
        
        first_rule = rules[0]
        
        # Check if both fields exist
        has_rule_text = 'rule_text' in first_rule
        has_raw_text = 'raw_text' in first_rule
        
        print(f"Rule ID: {first_rule.get('id', 'N/A')}")
        print(f"Has rule_text field: {has_rule_text}")
        print(f"Has raw_text field: {has_raw_text}")
        
        if has_rule_text:
            rule_text = first_rule['rule_text']
            print(f"Rule Text (processed): {rule_text[:100]}..." if len(str(rule_text)) > 100 else f"Rule Text (processed): {rule_text}")
        
        if has_raw_text:
            raw_text = first_rule['raw_text']
            print(f"Raw Text (original): {raw_text[:100]}..." if len(str(raw_text)) > 100 else f"Raw Text (original): {raw_text}")
        
        # Check if they're different (as expected)
        if has_rule_text and has_raw_text:
            are_different = first_rule['rule_text'] != first_rule['raw_text']
            print(f"Fields are different: {are_different}")
        
        print("-" * 50)
        print("✅ API test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing API: {str(e)}")

if __name__ == "__main__":
    test_api_response()