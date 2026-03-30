#!/usr/bin/env python3
"""
Test API endpoint directly
"""

import requests
import json

def test_api_direct():
    """Test the API endpoint directly"""
    try:
        # Test the normalized rules API
        response = requests.get('http://localhost:5001/api/normalized-rules?per_page=3')
        
        if response.status_code != 200:
            print(f"❌ API request failed with status: {response.status_code}")
            print(f"Response: {response.text}")
            return
        
        data = response.json()
        print(f"✅ API Response Status: {response.status_code}")
        print(f"✅ Total rules in response: {len(data.get('rules', []))}")
        print(f"✅ Total count: {data.get('total', 0)}")
        
        rules = data.get('rules', [])
        if rules:
            first_rule = rules[0]
            print("\n📋 First rule details:")
            print(f"  ID: {first_rule.get('id')}")
            print(f"  Has rule_text: {'rule_text' in first_rule}")
            print(f"  Has raw_text: {'raw_text' in first_rule}")
            
            if 'rule_text' in first_rule:
                rule_text = first_rule['rule_text']
                print(f"  Rule Text: {rule_text[:80]}...")
            
            if 'raw_text' in first_rule:
                raw_text = first_rule['raw_text']
                print(f"  Raw Text: {raw_text[:80]}...")
            
            # Check if they're different
            if 'rule_text' in first_rule and 'raw_text' in first_rule:
                are_different = first_rule['rule_text'] != first_rule['raw_text']
                print(f"  Fields are different: {are_different}")
        
        print("\n🎉 API test completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing API: {str(e)}")

if __name__ == "__main__":
    test_api_direct()