import requests
import sys
import time

BASE_URL = "http://localhost:5001/api"

def get_count():
    try:
        r = requests.get(f"{BASE_URL}/service-mappings?per_page=1")
        if r.status_code == 200:
            return r.json()['pagination']['total']
    except Exception as e:
        print(f"Error getting count: {e}")
    return 0

initial_count = get_count()
print(f"Initial count: {initial_count}")

print("Triggering IANA import...")
start_time = time.time()
r = requests.post(f"{BASE_URL}/service-mappings/import/iana-txt")
end_time = time.time()

if r.status_code == 200:
    print(f"Import success! Response: {r.json()}")
    print(f"Time taken: {end_time - start_time:.2f}s")
else:
    print(f"Import failed: {r.status_code} {r.text}")

final_count = get_count()
print(f"Final count: {final_count}")
print(f"Added: {final_count - initial_count}")
