#!/usr/bin/env python3
"""
Seed script to populate the service_port_mappings table with common well-known services
"""

from app import app, db
from models import ServicePortMapping

def seed_service_mappings():
    """Populate the service_port_mappings table with common services"""
    
    # Common well-known services and their port mappings
    services = [
        # Web Services
        {'service_name': 'HTTP', 'port_number': 80, 'protocol': 'tcp', 'description': 'Hypertext Transfer Protocol', 'category': 'web'},
        {'service_name': 'HTTPS', 'port_number': 443, 'protocol': 'tcp', 'description': 'HTTP Secure (SSL/TLS)', 'category': 'web'},
        {'service_name': 'HTTP-ALT', 'port_number': 8080, 'protocol': 'tcp', 'description': 'HTTP Alternative', 'category': 'web', 'is_well_known': False},
        {'service_name': 'HTTPS-ALT', 'port_number': 8443, 'protocol': 'tcp', 'description': 'HTTPS Alternative', 'category': 'web', 'is_well_known': False},
        
        # Remote Access
        {'service_name': 'SSH', 'port_number': 22, 'protocol': 'tcp', 'description': 'Secure Shell', 'category': 'remote_access'},
        {'service_name': 'TELNET', 'port_number': 23, 'protocol': 'tcp', 'description': 'Telnet Protocol', 'category': 'remote_access'},
        {'service_name': 'RDP', 'port_number': 3389, 'protocol': 'tcp', 'description': 'Remote Desktop Protocol', 'category': 'remote_access', 'is_well_known': False},
        {'service_name': 'VNC', 'port_number': 5900, 'protocol': 'tcp', 'description': 'Virtual Network Computing', 'category': 'remote_access', 'is_well_known': False},
        
        # File Transfer
        {'service_name': 'FTP', 'port_number': 21, 'protocol': 'tcp', 'description': 'File Transfer Protocol', 'category': 'file_transfer'},
        {'service_name': 'FTP-DATA', 'port_number': 20, 'protocol': 'tcp', 'description': 'FTP Data Transfer', 'category': 'file_transfer'},
        {'service_name': 'SFTP', 'port_number': 22, 'protocol': 'tcp', 'description': 'SSH File Transfer Protocol', 'category': 'file_transfer'},
        {'service_name': 'TFTP', 'port_number': 69, 'protocol': 'udp', 'description': 'Trivial File Transfer Protocol', 'category': 'file_transfer'},
        
        # Email Services
        {'service_name': 'SMTP', 'port_number': 25, 'protocol': 'tcp', 'description': 'Simple Mail Transfer Protocol', 'category': 'mail'},
        {'service_name': 'SMTPS', 'port_number': 465, 'protocol': 'tcp', 'description': 'SMTP Secure (SSL)', 'category': 'mail'},
        {'service_name': 'SMTP-SUBMISSION', 'port_number': 587, 'protocol': 'tcp', 'description': 'SMTP Message Submission', 'category': 'mail'},
        {'service_name': 'POP3', 'port_number': 110, 'protocol': 'tcp', 'description': 'Post Office Protocol v3', 'category': 'mail'},
        {'service_name': 'POP3S', 'port_number': 995, 'protocol': 'tcp', 'description': 'POP3 Secure (SSL)', 'category': 'mail'},
        {'service_name': 'IMAP', 'port_number': 143, 'protocol': 'tcp', 'description': 'Internet Message Access Protocol', 'category': 'mail'},
        {'service_name': 'IMAPS', 'port_number': 993, 'protocol': 'tcp', 'description': 'IMAP Secure (SSL)', 'category': 'mail'},
        
        # DNS Services
        {'service_name': 'DNS', 'port_number': 53, 'protocol': 'both', 'description': 'Domain Name System', 'category': 'network'},
        
        # Network Services
        {'service_name': 'DHCP-SERVER', 'port_number': 67, 'protocol': 'udp', 'description': 'DHCP Server', 'category': 'network'},
        {'service_name': 'DHCP-CLIENT', 'port_number': 68, 'protocol': 'udp', 'description': 'DHCP Client', 'category': 'network'},
        {'service_name': 'NTP', 'port_number': 123, 'protocol': 'udp', 'description': 'Network Time Protocol', 'category': 'network'},
        {'service_name': 'SNMP', 'port_number': 161, 'protocol': 'udp', 'description': 'Simple Network Management Protocol', 'category': 'network'},
        {'service_name': 'SNMP-TRAP', 'port_number': 162, 'protocol': 'udp', 'description': 'SNMP Trap', 'category': 'network'},
        {'service_name': 'SYSLOG', 'port_number': 514, 'protocol': 'udp', 'description': 'System Logging Protocol', 'category': 'network'},
        
        # Database Services
        {'service_name': 'MYSQL', 'port_number': 3306, 'protocol': 'tcp', 'description': 'MySQL Database', 'category': 'database', 'is_well_known': False},
        {'service_name': 'POSTGRESQL', 'port_number': 5432, 'protocol': 'tcp', 'description': 'PostgreSQL Database', 'category': 'database', 'is_well_known': False},
        {'service_name': 'MSSQL', 'port_number': 1433, 'protocol': 'tcp', 'description': 'Microsoft SQL Server', 'category': 'database', 'is_well_known': False},
        {'service_name': 'ORACLE', 'port_number': 1521, 'protocol': 'tcp', 'description': 'Oracle Database', 'category': 'database', 'is_well_known': False},
        {'service_name': 'MONGODB', 'port_number': 27017, 'protocol': 'tcp', 'description': 'MongoDB Database', 'category': 'database', 'is_well_known': False},
        {'service_name': 'REDIS', 'port_number': 6379, 'protocol': 'tcp', 'description': 'Redis Database', 'category': 'database', 'is_well_known': False},
        
        # Directory Services
        {'service_name': 'LDAP', 'port_number': 389, 'protocol': 'tcp', 'description': 'Lightweight Directory Access Protocol', 'category': 'directory'},
        {'service_name': 'LDAPS', 'port_number': 636, 'protocol': 'tcp', 'description': 'LDAP Secure (SSL)', 'category': 'directory'},
        {'service_name': 'KERBEROS', 'port_number': 88, 'protocol': 'both', 'description': 'Kerberos Authentication', 'category': 'directory'},
        
        # Application Services
        {'service_name': 'ELASTICSEARCH', 'port_number': 9200, 'protocol': 'tcp', 'description': 'Elasticsearch HTTP API', 'category': 'application', 'is_well_known': False},
        {'service_name': 'KIBANA', 'port_number': 5601, 'protocol': 'tcp', 'description': 'Kibana Web Interface', 'category': 'application', 'is_well_known': False},
        {'service_name': 'GRAFANA', 'port_number': 3000, 'protocol': 'tcp', 'description': 'Grafana Dashboard', 'category': 'application', 'is_well_known': False},
        {'service_name': 'PROMETHEUS', 'port_number': 9090, 'protocol': 'tcp', 'description': 'Prometheus Monitoring', 'category': 'application', 'is_well_known': False},
        
        # Security Services
        {'service_name': 'RADIUS', 'port_number': 1812, 'protocol': 'udp', 'description': 'RADIUS Authentication', 'category': 'security', 'is_well_known': False},
        {'service_name': 'RADIUS-ACCT', 'port_number': 1813, 'protocol': 'udp', 'description': 'RADIUS Accounting', 'category': 'security', 'is_well_known': False},
        {'service_name': 'TACACS', 'port_number': 49, 'protocol': 'tcp', 'description': 'TACACS+ Authentication', 'category': 'security'},
        
        # Messaging Services
        {'service_name': 'MQTT', 'port_number': 1883, 'protocol': 'tcp', 'description': 'Message Queuing Telemetry Transport', 'category': 'messaging', 'is_well_known': False},
        {'service_name': 'MQTTS', 'port_number': 8883, 'protocol': 'tcp', 'description': 'MQTT Secure (SSL)', 'category': 'messaging', 'is_well_known': False},
        {'service_name': 'AMQP', 'port_number': 5672, 'protocol': 'tcp', 'description': 'Advanced Message Queuing Protocol', 'category': 'messaging', 'is_well_known': False},
        
        # Network Management
        {'service_name': 'NETBIOS-NS', 'port_number': 137, 'protocol': 'udp', 'description': 'NetBIOS Name Service', 'category': 'network'},
        {'service_name': 'NETBIOS-DGM', 'port_number': 138, 'protocol': 'udp', 'description': 'NetBIOS Datagram Service', 'category': 'network'},
        {'service_name': 'NETBIOS-SSN', 'port_number': 139, 'protocol': 'tcp', 'description': 'NetBIOS Session Service', 'category': 'network'},
        {'service_name': 'SMB', 'port_number': 445, 'protocol': 'tcp', 'description': 'Server Message Block', 'category': 'file_transfer'},
        
        # Virtualization
        {'service_name': 'VMWARE-CONSOLE', 'port_number': 902, 'protocol': 'tcp', 'description': 'VMware Console', 'category': 'virtualization', 'is_well_known': False},
        {'service_name': 'VMWARE-AUTHD', 'port_number': 903, 'protocol': 'tcp', 'description': 'VMware Authentication', 'category': 'virtualization', 'is_well_known': False},
        {'service_name': 'HYPER-V', 'port_number': 2179, 'protocol': 'tcp', 'description': 'Hyper-V Management', 'category': 'virtualization', 'is_well_known': False},
    ]
    
    with app.app_context():
        try:
            # Clear existing mappings
            print("Clearing existing service mappings...")
            ServicePortMapping.query.delete()
            
            # Add new mappings
            print(f"Adding {len(services)} service mappings...")
            for service_data in services:
                mapping = ServicePortMapping(
                    service_name=service_data['service_name'],
                    port_number=service_data['port_number'],
                    protocol=service_data['protocol'],
                    description=service_data['description'],
                    category=service_data['category'],
                    is_well_known=service_data.get('is_well_known', True),
                    is_active=True
                )
                db.session.add(mapping)
            
            # Commit all changes
            db.session.commit()
            
            # Verify the seeding
            total_mappings = ServicePortMapping.query.count()
            well_known_count = ServicePortMapping.query.filter_by(is_well_known=True).count()
            
            print(f"Successfully seeded {total_mappings} service mappings")
            print(f"- Well-known ports (0-1023): {well_known_count}")
            print(f"- Registered/Private ports: {total_mappings - well_known_count}")
            
            # Show categories
            categories = db.session.query(ServicePortMapping.category).distinct().all()
            print(f"- Categories: {', '.join([cat[0] for cat in categories])}")
            
        except Exception as e:
            print(f"Error seeding service mappings: {str(e)}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    seed_service_mappings()