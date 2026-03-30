
import re

pattern = r'.*(?i)(citrix|pim|pam|bastion|jump).*'
text = '1.2.3.4'

match = re.search(pattern, text, re.IGNORECASE)
print(f"Pattern: {pattern}")
print(f"Text: {text}")
print(f"Match: {match}")
