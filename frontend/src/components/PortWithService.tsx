import React, { useState, useEffect } from 'react';
import { Chip, Tooltip, Box, Typography } from '@mui/material';
import { lookupServicesByPort } from '../utils/serviceMapping';

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

interface PortWithServiceProps {
  port: string | number;
  protocol?: string;
  variant?: 'chip' | 'text';
  size?: 'small' | 'medium';
  showTooltip?: boolean;
}

const PortWithService: React.FC<PortWithServiceProps> = ({
  port,
  protocol,
  variant = 'chip',
  size = 'small',
  showTooltip = true
}) => {
  const [services, setServices] = useState<ServiceMapping[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchServices = async () => {
      setLoading(true);
      try {
        const portNum = typeof port === 'string' ? parseInt(port) : port;
        if (!isNaN(portNum) && portNum > 0) {
          const serviceList = await lookupServicesByPort(portNum, protocol);
          setServices(serviceList);
        }
      } catch (error) {
        console.error('Error fetching services for port:', port, error);
      } finally {
        setLoading(false);
      }
    };

    fetchServices();
  }, [port, protocol]);

  const portNum = typeof port === 'string' ? parseInt(port) : port;
  const isValidPort = !isNaN(portNum) && portNum > 0;
  
  if (!isValidPort) {
    return variant === 'chip' ? (
      <Chip label={port} size={size} variant="outlined" />
    ) : (
      <Typography variant="body2">{port}</Typography>
    );
  }

  const primaryService = services.length > 0 ? services[0] : null;
  const displayText = primaryService ? `${port} (${primaryService.service_name})` : port.toString();
  
  const tooltipContent = services.length > 0 ? (
    <Box>
      <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 1 }}>
        Port {port} Services:
      </Typography>
      {services.map((service, index) => (
        <Box key={service.id} sx={{ mb: index < services.length - 1 ? 1 : 0 }}>
          <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
            {service.service_name} ({service.protocol.toUpperCase()})
          </Typography>
          {service.description && (
            <Typography variant="caption" color="text.secondary">
              {service.description}
            </Typography>
          )}
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            Category: {service.category}
            {service.is_well_known && ' • Well-known port'}
          </Typography>
        </Box>
      ))}
    </Box>
  ) : (
    <Typography variant="body2">
      Port {port} - No known service mapping
    </Typography>
  );

  const content = variant === 'chip' ? (
    <Chip
      label={displayText}
      size={size}
      variant="outlined"
      color={primaryService ? 'primary' : 'default'}
      sx={{
        mr: 0.5,
        mb: 0.5,
        '& .MuiChip-label': {
          maxWidth: '200px',
          overflow: 'hidden',
          textOverflow: 'ellipsis'
        }
      }}
    />
  ) : (
    <Typography 
      variant="body2" 
      color={primaryService ? 'primary' : 'text.primary'}
      sx={{ 
        fontWeight: primaryService ? 'medium' : 'normal',
        maxWidth: '200px',
        overflow: 'hidden',
        textOverflow: 'ellipsis'
      }}
    >
      {displayText}
    </Typography>
  );

  return showTooltip ? (
    <Tooltip title={tooltipContent} arrow placement="top">
      {content}
    </Tooltip>
  ) : content;
};

export default PortWithService;