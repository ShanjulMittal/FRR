
import csv
import io

def test_whitespace_header():
    # CSV with space in header "Addresses "
    csv_content = 'Name,Addresses \nTest,1.1.1.1'
    
    # Frontend sends mapping using the exact header "Addresses "
    frontend_mapping = {
        "Name": ["name"],
        "Addresses ": ["members"]
    }
    
    # Backend Logic
    
    # 1. Inversion
    internal_mapping = {}
    for csv_col, internal_fields in frontend_mapping.items():
        if isinstance(internal_fields, list):
            for field in internal_fields:
                if field not in internal_mapping:
                    internal_mapping[field] = []
                internal_mapping[field].append(csv_col) # Appends "Addresses "
    
    mapping = internal_mapping
    print(f"Mapping: {mapping}")
    
    # 2. Reading
    f = io.StringIO(csv_content)
    reader = csv.DictReader(f)
    
    # 3. Stripping Headers
    reader.fieldnames = [h.strip() for h in reader.fieldnames]
    print(f"Stripped Headers: {reader.fieldnames}")
    
    # 4. Processing
    for row in reader:
        print(f"Row Keys: {list(row.keys())}")
        
        # Look up
        cols = mapping['members'] # ['Addresses ']
        found = False
        for col in cols:
            print(f"Checking col '{col}' in row keys...")
            if col in row:
                print("FOUND!")
                found = True
            else:
                print("NOT FOUND!")
        
        if not found:
            print("FAILURE: Mapping mismatch due to whitespace.")

if __name__ == "__main__":
    test_whitespace_header()
