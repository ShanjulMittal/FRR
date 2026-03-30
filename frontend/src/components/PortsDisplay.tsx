import React, { useState, useEffect } from 'react';
import { Box, Chip, Typography } from '@mui/material';
import { parsePortsWithServices, parseMultiplePortsWithServices } from '../utils/serviceMapping';

interface PortWithService {
  port: string;
  serviceName?: string;
  fullDisplay: string;
}

interface PortsDisplayProps {
  protocol: string;
  destPort?: string;
  maxVisible?: number;
  size?: 'small' | 'medium';
}

const PortsDisplay: React.FC<PortsDisplayProps> = ({
  protocol,
  destPort,
  maxVisible = 3,
  size = 'small'
}) => {
  const [ports, setPorts] = useState<PortWithService[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchPortsWithServices = async () => {
      setLoading(true);
      try {
        // First try to use the destination port if available
        if (destPort && destPort.trim()) {
          const destPortsWithServices = await parseMultiplePortsWithServices(destPort, protocol);
          setPorts(destPortsWithServices);
        } else {
          // Fallback to parsing protocol if no destination port
          const portsWithServices = await parsePortsWithServices(protocol);
          setPorts(portsWithServices);
        }
      } catch (error) {
        console.error('Error parsing ports with services:', error);
        // Fallback to basic port parsing
        let basicPorts: string[] = [];
        
        // Try destination port first, then protocol
        if (destPort && destPort.trim()) {
          basicPorts = parsePortsBasic(destPort);
        } else {
          basicPorts = parsePortsBasic(protocol);
        }
        
        setPorts(basicPorts.map(port => ({
          port,
          fullDisplay: port
        })));
      } finally {
        setLoading(false);
      }
    };

    fetchPortsWithServices();
  }, [protocol, destPort]);

  // Fallback function for basic port parsing (same as original)
  const parsePortsBasic = (protocolStr: string): string[] => {
    if (!protocolStr) return [];
    const portList: string[] = [];
    const parts = protocolStr.split(';');
    
    parts.forEach(part => {
      const match = part.match(/TCP-(\d+)|UDP-(\d+)|(\d+)/);
      if (match) {
        const port = match[1] || match[2] || match[3];
        if (port && !portList.includes(port)) {
          portList.push(port);
        }
      }
    });
    
    return portList;
  };

  if (loading) {
    return (
      <Box>
        <Typography variant="body2" color="text.secondary">
          Loading ports...
        </Typography>
      </Box>
    );
  }

  if (ports.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        N/A
      </Typography>
    );
  }

  const visiblePorts = ports.slice(0, maxVisible);
  const remainingCount = ports.length - maxVisible;

  return (
    <Box>
      {visiblePorts.map((portInfo, index) => (
        <Chip
          key={index}
          label={portInfo.fullDisplay}
          size={size}
          variant="outlined"
          color={portInfo.serviceName ? 'primary' : 'default'}
          sx={{ 
            mr: 0.5, 
            mb: 0.5,
            '& .MuiChip-label': {
              maxWidth: '180px',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }
          }}
        />
      ))}
      {remainingCount > 0 && (
        <Chip
          label={`+${remainingCount}`}
          size={size}
          variant="outlined"
          sx={{ mr: 0.5, mb: 0.5 }}
        />
      )}
    </Box>
  );
};

export default PortsDisplay;