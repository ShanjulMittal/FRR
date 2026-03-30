// Service mapping utilities for port-to-service lookups

interface ServiceMapping {
  id: number;
  service_name: string;
  port_number: number;
  protocol: string;
  description: string;
  category: string;
  is_well_known: boolean;
  is_active: boolean;
}

interface ServiceLookupCache {
  [key: string]: ServiceMapping[];
}

// Cache for service mappings to avoid repeated API calls
let serviceMappingCache: ServiceLookupCache = {};
let cacheExpiry: number = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

/**
 * Fetch service mappings from the API
 */
export const fetchServiceMappings = async (): Promise<ServiceMapping[]> => {
  try {
    const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
    const response = await fetch(`${API_BASE_URL}/api/service-mappings?per_page=1000`);
    if (!response.ok) {
      throw new Error('Failed to fetch service mappings');
    }
    const data = await response.json();
    return data.mappings || [];
  } catch (error) {
    console.error('Error fetching service mappings:', error);
    return [];
  }
};

/**
 * Get service mappings with caching
 */
export const getServiceMappings = async (): Promise<ServiceMapping[]> => {
  const now = Date.now();
  
  // Check if cache is still valid
  if (cacheExpiry > now && Object.keys(serviceMappingCache).length > 0) {
    return Object.values(serviceMappingCache).flat();
  }
  
  // Fetch fresh data
  const mappings = await fetchServiceMappings();
  
  // Update cache
  serviceMappingCache = {};
  mappings.forEach(mapping => {
    const protoLower = (mapping.protocol || '').toLowerCase();
    const key = `${mapping.port_number}-${protoLower}`;
    if (!serviceMappingCache[key]) {
      serviceMappingCache[key] = [];
    }
    serviceMappingCache[key].push(mapping);
    // Normalize common "both" indicator variants
    if (protoLower === 'tcp/udp' || protoLower === 'tcp_udp' || protoLower === 'both') {
      const bothKey = `${mapping.port_number}-both`;
      if (!serviceMappingCache[bothKey]) {
        serviceMappingCache[bothKey] = [];
      }
      serviceMappingCache[bothKey].push(mapping);
    }
  });
  
  cacheExpiry = now + CACHE_DURATION;
  return mappings;
};

/**
 * Lookup services by port number and protocol
 */
export const lookupServicesByPort = async (
  portNumber: number, 
  protocol?: string
): Promise<ServiceMapping[]> => {
  await getServiceMappings(); // Ensure cache is populated
  const results: ServiceMapping[] = [];
  if (protocol) {
    const protocolLower = protocol.toLowerCase();
    const exactKey = `${portNumber}-${protocolLower}`;
    const bothKey = `${portNumber}-both`;
    if (serviceMappingCache[exactKey]) {
      results.push(...serviceMappingCache[exactKey]);
    }
    if (serviceMappingCache[bothKey]) {
      results.push(...serviceMappingCache[bothKey]);
    }
    // Fallback: if no matches with protocol, try any protocol
    if (results.length === 0) {
      Object.keys(serviceMappingCache).forEach(key => {
        if (key.startsWith(`${portNumber}-`)) {
          results.push(...serviceMappingCache[key]);
        }
      });
    }
  } else {
    Object.keys(serviceMappingCache).forEach(key => {
      if (key.startsWith(`${portNumber}-`)) {
        results.push(...serviceMappingCache[key]);
      }
    });
  }
  return results;
};

/**
 * Lookup port by service name
 */
export const lookupPortByService = async (serviceName: string, protocol?: string): Promise<ServiceMapping | null> => {
  const mappings = await getServiceMappings();
  const target = serviceName.toLowerCase();
  const candidates = mappings.filter(m => m.service_name.toLowerCase() === target);
  if (candidates.length === 0) return null;
  if (!protocol) return candidates[0] || null;
  const protoLower = protocol.toLowerCase();
  const exact = candidates.find(m => (m.protocol || '').toLowerCase() === protoLower);
  if (exact) return exact;
  const both = candidates.find(m => ['both', 'tcp/udp', 'tcp_udp'].includes((m.protocol || '').toLowerCase()));
  return both || candidates[0] || null;
};

/**
 * Format port with service name for display
 */
export const formatPortWithService = async (
  portNumber: number | string, 
  protocol?: string
): Promise<string> => {
  const port = typeof portNumber === 'string' ? parseInt(portNumber) : portNumber;
  
  if (isNaN(port) || port <= 0) {
    return portNumber.toString();
  }
  
  const services = await lookupServicesByPort(port, protocol);
  
  if (services.length === 0) {
    return port.toString();
  }
  
  // Return the first (most relevant) service name with port
  const primaryService = services[0];
  return `${port} (${primaryService.service_name})`;
};

/**
 * Get service name for a port (without the port number)
 */
export const getServiceName = async (
  portNumber: number | string, 
  protocol?: string
): Promise<string | null> => {
  const port = typeof portNumber === 'string' ? parseInt(portNumber) : portNumber;
  
  if (isNaN(port) || port <= 0) {
    return null;
  }
  
  const services = await lookupServicesByPort(port, protocol);
  return services.length > 0 ? services[0].service_name : null;
};

/**
 * Parse ports from protocol string and return with service names
 */
export const parsePortsWithServices = async (protocol: string): Promise<Array<{
  port: string;
  serviceName?: string;
  fullDisplay: string;
}>> => {
  if (!protocol) return [];
  
  const tokens = protocol
    .split(/[;,]/)
    .map((p) => p.trim())
    .filter(Boolean);

  const results = await Promise.all(
    tokens.map(async (token) => {
      const { port, protocol: tokenProto } = extractPortProtocol(token);
      if (port == null) {
        // Could be plain service name in protocol string, attempt lookup
        const mapping = await lookupPortByService(token, tokenProto);
        if (mapping) {
          const label = String(mapping.port_number);
          const full = `${label} (${mapping.service_name})`;
          return { port: label, serviceName: mapping.service_name, fullDisplay: full };
        }
        return { port: token, fullDisplay: token };
      }
      const services = await lookupServicesByPort(port, tokenProto);
      const names = Array.from(new Set(services.map((s) => s.service_name)));
      const label = token.match(/^(\d+)-(\d+)$/) ? token : String(port);
      const full = names.length > 0 ? `${label} (${names.join('/')})` : label;
      return { port: label, serviceName: names.join('/'), fullDisplay: full };
    })
  );

  return results;
};

/**
 * Parse multiple ports from destination port field (semicolon-separated)
 */
// Helper to extract port and protocol from mixed tokens like "TCP-80", "80/TCP", "udp:53"
const extractPortProtocol = (token: string): { port: number | null; protocol?: string } => {
  if (!token) return { port: null };
  const t = token.trim();
  // 1) PROTOCOL/PORT or PROTOCOL-PORT or PROTOCOL:PORT
  let m = t.match(/^([a-zA-Z]+)[\/:-](\d+)$/);
  if (m) {
    const protocol = m[1].toLowerCase();
    const port = parseInt(m[2], 10);
    return { port: isNaN(port) ? null : port, protocol };
  }
  // 2) PORT/PROTOCOL
  m = t.match(/^(\d+)[\/:-]([a-zA-Z]+)$/);
  if (m) {
    const port = parseInt(m[1], 10);
    const protocol = m[2].toLowerCase();
    return { port: isNaN(port) ? null : port, protocol };
  }
  // 3) PURE NUMBER
  m = t.match(/^(\d+)$/);
  if (m) {
    const port = parseInt(m[1], 10);
    return { port: isNaN(port) ? null : port };
  }
  // 4) RANGE like 1521-1523: use start port for mapping, keep range string as label
  m = t.match(/^(\d+)-(\d+)$/);
  if (m) {
    const start = parseInt(m[1], 10);
    return { port: isNaN(start) ? null : start };
  }
  // 5) Service name (HTTPS, SSH, etc.)
  return { port: null };
};

export const parseMultiplePortsWithServices = async (destPort: string, protocol?: string): Promise<Array<{
  port: string;
  serviceName?: string;
  fullDisplay: string;
}>> => {
  if (!destPort) return [];
  const tokens: string[] = destPort
    .split(/[;,]/) // handle both ';' and ',' separators
    .map(p => p.trim())
    .filter(Boolean);

  const portsWithServices = await Promise.all(
    tokens.map(async (token) => {
      // Attempt robust extraction of port/protocol
      const { port, protocol: tokenProto } = extractPortProtocol(token);

      // Prefer protocol from token; otherwise use provided protocol
      const effectiveProtocol = tokenProto || protocol;

      // If token looks like a service name (no port), try lookup by service name
      if (port == null) {
        const mapping = await lookupPortByService(token, effectiveProtocol);
        if (mapping) {
          const svcName = mapping.service_name;
          const display = `${mapping.port_number} (${svcName})`;
          return { port: String(mapping.port_number), serviceName: svcName, fullDisplay: display };
        }
        // No mapping: show token as-is
        return { port: token, fullDisplay: token };
      }

      const services = await lookupServicesByPort(port, effectiveProtocol);
      const names = Array.from(new Set(services.map((s) => s.service_name)));
      const label = token.match(/^(\d+)-(\d+)$/) ? token : String(port); // preserve range token label
      const fullDisplay = names.length > 0 ? `${label} (${names.join('/')})` : label;
      return { port: label, serviceName: names.join('/'), fullDisplay };
    })
  );

  return portsWithServices;
};

/**
 * Clear the service mapping cache (useful for testing or manual refresh)
 */
export const clearServiceMappingCache = (): void => {
  serviceMappingCache = {};
  cacheExpiry = 0;
};
