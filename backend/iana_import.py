import csv
import io
import requests
import logging
from models import db, ServicePortMapping

logger = logging.getLogger(__name__)

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

def import_iana_service_mappings():
    try:
        logger.info("Fetching IANA service mappings...")
        response = requests.get(IANA_CSV_URL, timeout=30)
        response.raise_for_status()
        
        content = response.content.decode('utf-8', errors='replace')
        csv_file = io.StringIO(content)
        reader = csv.DictReader(csv_file)
        
        # Track unique service names to handle duplicates
        # Map: service_name -> {port: int, protocols: set, description: str}
        services = {}
        
        for row in reader:
            service_name = row.get('Service Name', '').strip()
            port_str = row.get('Port Number', '').strip()
            protocol = row.get('Transport Protocol', '').strip().lower()
            description = row.get('Description', '').strip()
            
            if not service_name or not port_str or not protocol:
                continue
                
            # Skip unassigned
            if service_name.lower() == 'unassigned':
                continue
                
            # Handle port ranges - take start port for now or skip
            # IANA often puts ranges like "6000-6063"
            if '-' in port_str:
                continue 
                
            try:
                port = int(port_str)
            except ValueError:
                continue
                
            if service_name not in services:
                services[service_name] = {
                    'port': port,
                    'protocols': {protocol},
                    'description': description
                }
            else:
                # Collision on service name
                existing = services[service_name]
                if existing['port'] == port:
                    # Same port, add protocol
                    existing['protocols'].add(protocol)
                    if description and not existing['description']:
                        existing['description'] = description
                else:
                    # Same name, different port. 
                    # Use suffixed name for the new one to avoid collision
                    new_name = f"{service_name}-{port}"
                    if new_name not in services:
                        services[new_name] = {
                            'port': port,
                            'protocols': {protocol},
                            'description': description
                        }
        
        # Sync with DB
        existing_mappings = {m.service_name: m for m in ServicePortMapping.query.all()}
        
        new_objects = []
        updated_count = 0
        created_count = 0
        
        # Use a limit to avoid overwhelming the DB/UI if IANA has too many (it has >10k)
        # But user asked for import. We'll import all valid ones.
        
        for name, data in services.items():
            protocols = data['protocols']
            if 'tcp' in protocols and 'udp' in protocols:
                proto = 'both'
            else:
                proto = list(protocols)[0]
                
            port = data['port']
            desc = data['description']
            
            if name in existing_mappings:
                # Update existing
                mapping = existing_mappings[name]
                mapping.port_number = port
                mapping.protocol = proto
                if desc:
                    mapping.description = desc
                updated_count += 1
            else:
                # Create new
                mapping = ServicePortMapping(
                    service_name=name,
                    port_number=port,
                    protocol=proto,
                    description=desc,
                    category='iana',
                    is_well_known=(port < 1024),
                    is_active=True
                )
                new_objects.append(mapping)
                created_count += 1
        
        if new_objects:
            # Chunk the inserts to be safe with SQLite limits
            chunk_size = 500
            for i in range(0, len(new_objects), chunk_size):
                db.session.bulk_save_objects(new_objects[i:i+chunk_size])
                db.session.commit() # Commit each chunk
        else:
             db.session.commit()
             
        logger.info(f"IANA Import: Created {created_count}, Updated {updated_count}")
        return {'created': created_count, 'updated': updated_count}
        
    except Exception as e:
        logger.error(f"IANA Import failed: {e}")
        db.session.rollback()
        raise e
