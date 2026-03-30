
import csv
import io
import re
import json

def test_import_logic():
    # Simulate CSV content with BOM and quoted newlines (Excel style)
    csv_content = b'\xef\xbb\xbfName,Addresses\nTestGroup1,"10.0.0.1\n10.0.0.2"\nTestGroup2,192.168.1.1'
    
    # Simulate mapping from frontend: { "CSV_Column": ["Internal_Field"] }
    # User said: Name -> Name, Addresses -> Members
    # Internal fields: 'name', 'members'
    frontend_mapping = {
        "Name": ["name"],
        "Addresses": ["members"]
    }
    
    print(f"Frontend Mapping: {frontend_mapping}")
    
    # 1. Backend Inversion Logic
    internal_mapping = {}
    for csv_col, internal_fields in frontend_mapping.items():
        if isinstance(internal_fields, list):
            for field in internal_fields:
                if field not in internal_mapping:
                    internal_mapping[field] = []
                internal_mapping[field].append(csv_col)
        else:
            field = internal_fields
            if field not in internal_mapping:
                internal_mapping[field] = []
            internal_mapping[field].append(csv_col)
    
    mapping = internal_mapping
    print(f"Backend Mapping (Inverted): {mapping}")
    
    # 2. File Reading & Decoding
    try:
        text_content = csv_content.decode('utf-8-sig')
    except UnicodeDecodeError:
        text_content = csv_content.decode('latin-1')
        
    # 3. Comment Filtering
    lines = [line for line in text_content.splitlines() if line.strip() and not line.strip().startswith('#')]
    
    # 4. CSV Parsing
    stream = io.StringIO('\n'.join(lines), newline=None)
    reader = csv.DictReader(stream)
    
    # Header Normalization
    if reader.fieldnames:
        reader.fieldnames = [h.strip() for h in reader.fieldnames]
    
    print(f"CSV Headers: {reader.fieldnames}")
    
    # 5. Row Processing
    for i, row in enumerate(reader):
        print(f"\n--- Row {i} ---")
        print(f"Raw Row: {row}")
        
        group_data = {}
        for field, cols in mapping.items():
            val = None
            if isinstance(cols, list):
                for col in cols:
                    if col in row and row[col]:
                        val = row[col]
                        break
            else:
                if cols in row:
                    val = row[cols]
            
            if val is not None:
                group_data[field] = val.strip()
        
        name = group_data.get('name')
        members_str = group_data.get('members', '')
        
        print(f"Extracted Name: '{name}'")
        print(f"Extracted Members Str: '{members_str}'") # repr to see newlines
        
        # 6. Member Splitting Logic
        members = [m.strip() for m in members_str.split('\n') if m.strip()]
        if not members:
            members = [m.strip() for m in re.split(r'[,\s]+', members_str) if m.strip()]
            
        print(f"Final Members List: {members}")
        
        if not members:
            print("FAILURE: No members extracted!")
        else:
            print("SUCCESS: Members extracted.")

if __name__ == "__main__":
    test_import_logic()
