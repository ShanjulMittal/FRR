import React, { useState, useEffect, useCallback } from 'react';


import {
  Container,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  TextField,
  Box,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  CircularProgress,
  Pagination,
  TableSortLabel,
  IconButton,
  Menu,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tooltip,
  Alert,
  Snackbar,
  Checkbox,
} from '@mui/material';
import PortsDisplay from '../components/PortsDisplay';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  Delete as DeleteIcon,
  DeleteSweep as DeleteSweepIcon,
  MoreVert as MoreVertIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

type CMDBMatch = {
  hostname?: string;
  ip_address?: string;
  owner?: string;
  department?: string;
  environment?: string;
  asset_type?: string;
  operating_system?: string;
  model?: string;
  manufacturer?: string;
  application?: string;
  location?: string;
  business_unit?: string;
  pcidss_asset_category?: string;
};

interface NormalizedRule {
  id: number;
  source_file: string;
  action: string;
  protocol: string;
  source_ip: string;
  source_ip_with_zone?: string; // Source IP with zone AND logic
  source_zone?: string;
  dest_ip: string;
  dest_ip_with_zone?: string; // Destination IP with zone AND logic
  dest_zone?: string;
  dest_port: string;
  service_name: string;
  hit_count?: number;
  compliance_status: string;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
  rule_name?: string;
  raw_rule_name?: string;
  custom_fields_data?: {
    rule_name?: string;
    [key: string]: any;
  };
  raw_rule_id?: number; // Added to enable grouping by original raw rule
  source_hostname?: string;
  source_owner?: string;
  source_department?: string;
  source_environment?: string;
  source_vlan_id?: number;
  source_vlan_name?: string;
  source_subnet?: string;
  source_location?: string;
  dest_hostname?: string;
  dest_owner?: string;
  dest_department?: string;
  dest_environment?: string;
  dest_vlan_id?: number;
  dest_vlan_name?: string;
  dest_subnet?: string;
  dest_location?: string;
  source_cmdb_matches?: CMDBMatch[];
  dest_cmdb_matches?: CMDBMatch[];
  raw_text?: string;
  rule_text?: string;
  raw_data?: any;
  cmdb_available_fields?: string[];
}

interface FilterState {
  search: string;
  source_file: string;
  action: string;
  protocol: string;
  compliance_status: string;
  search_scope: string;
  search_fields: string;
}

const NormalizedRules: React.FC = () => {
  const [rules, setRules] = useState<NormalizedRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sourceFiles, setSourceFiles] = useState<string[]>([]);
  
  // Pagination
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalRules, setTotalRules] = useState(0);
  const [perPage] = useState(25);
  
  // Filtering and sorting
  const [filters, setFilters] = useState<FilterState>({
    search: '',
    source_file: '',
    action: '',
    protocol: '',
    compliance_status: '',
    search_scope: 'all',
    search_fields: '',
  });
  // Applied filters state for search execution
  const [appliedFilters, setAppliedFilters] = useState<FilterState>({
    search: '',
    source_file: '',
    action: '',
    protocol: '',
    compliance_status: '',
    search_scope: 'all',
    search_fields: '',
  });
  const [sortBy, setSortBy] = useState('id');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedIds, setSelectedIds] = useState<number[]>([]);

  // Dialog states
  const [selectedRule, setSelectedRule] = useState<NormalizedRule | null>(null);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [bulkDeleteDialogOpen, setBulkDeleteDialogOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editData, setEditData] = useState<any>({});

  // Snackbar state
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });

  // Bulk delete state
  const [bulkDeleting, setBulkDeleting] = useState(false);

  // Helper function to get rule name from either direct field or custom fields
  const getRuleName = (rule: NormalizedRule): string => {
    if (rule.rule_name) {
      return rule.rule_name;
    }
    if (rule.raw_rule_name) {
      return rule.raw_rule_name;
    }
    if (rule.custom_fields_data?.rule_name) {
      return rule.custom_fields_data.rule_name;
    }
    return `Rule ${rule.id}`;
  };

  // Group normalized rules by origin and aggregate ports for display
  const getGroupKey = (rule: NormalizedRule): string => {
    const base =
      rule.raw_rule_id != null
        ? String(rule.raw_rule_id)
        : `${getRuleName(rule)}|${rule.source_ip}|${rule.dest_ip}|${rule.action}|${rule.protocol}|${rule.source_file}`;
    return base;
  };

  const getAggregatedPorts = (rule: NormalizedRule, allRules: NormalizedRule[]): string => {
    const key = getGroupKey(rule);
    const ports = new Set<string>();
    for (const r of allRules) {
      if (getGroupKey(r) === key) {
        (r.dest_port || '')
          .split(';')
          .map((p) => p.trim())
          .filter(Boolean)
          .forEach((p) => ports.add(p));
      }
    }
    return Array.from(ports).join(';');
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, rule: NormalizedRule) => {
    setAnchorEl(event.currentTarget);
    setSelectedRule(rule);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleViewRule = async () => {
    try {
      if (selectedRule) {
        const resp = await fetch(`${API_BASE_URL}/api/normalized-rules/${selectedRule.id}/details`);
        if (resp.ok) {
          const data = await resp.json();
          setSelectedRule(data as NormalizedRule);
        }
      }
    } catch (e) {
      console.error('Failed to load rule details', e);
    } finally {
      setViewDialogOpen(true);
      handleMenuClose();
    }
  };

  const handleDeleteRule = () => {
    setDeleteDialogOpen(true);
    handleMenuClose();
  };

  const handleBulkDelete = () => {
    setBulkDeleteDialogOpen(true);
  };

  const confirmDelete = async () => {
    if (!selectedRule) return;
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/normalized-rules/${selectedRule.id}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        await fetchRules();
        setDeleteDialogOpen(false);
        setSelectedRule(null);
        setSnackbar({ open: true, message: 'Rule deleted successfully', severity: 'success' });
      } else {
        throw new Error('Failed to delete rule');
      }
    } catch (err) {
      console.error('Error deleting rule:', err);
      setSnackbar({ open: true, message: 'Failed to delete rule', severity: 'error' });
    }
  };

  const confirmBulkDelete = async () => {
    setBulkDeleting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/normalized-rules/bulk-delete`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ delete_all: true }),
      });
      
      if (response.ok) {
        const data = await response.json();
        await fetchRules();
        setBulkDeleteDialogOpen(false);
        setSnackbar({ 
          open: true, 
          message: data.message || 'All rules deleted successfully', 
          severity: 'success' 
        });
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete all rules');
      }
    } catch (err) {
      console.error('Error deleting all rules:', err);
      setSnackbar({ 
        open: true, 
        message: err instanceof Error ? err.message : 'Failed to delete all rules', 
        severity: 'error' 
      });
    } finally {
      setBulkDeleting(false);
    }
  };

  // Fetch source files for filter dropdown
  const fetchSourceFiles = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/source-files`);
      if (response.ok) {
        const data = await response.json();
        setSourceFiles(data.source_files || []);
      }
    } catch (err) {
      console.error('Failed to fetch source files:', err);
    }
  }, []);

  // Fetch normalized rules
  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString(),
        sort_by: sortBy,
        sort_order: sortOrder,
      });

      // Add filters
      Object.entries(appliedFilters).forEach(([key, value]) => {
        if (value) {
          params.append(key, value.toString());
        }
      });

      const response = await fetch(`${API_BASE_URL}/api/normalized-rules?${params}`);
      if (!response.ok) {
        throw new Error('Failed to fetch normalized rules');
      }

      const data = await response.json();
      setRules(data.normalized_rules || []);
      setTotalPages(data.pages || 1);
      setTotalRules(data.total || 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch normalized rules');
    } finally {
      setLoading(false);
    }
  }, [page, perPage, sortBy, sortOrder, appliedFilters]);

  // Initial load
  useEffect(() => {
    fetchRules();
    fetchSourceFiles();
  }, [fetchRules, fetchSourceFiles]);

  const handleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('asc');
    }
  };

  const handleFilterChange = (key: keyof FilterState, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleSearch = () => {
    setPage(1);
    setAppliedFilters(filters);
  };

  const getActionColor = (action: string) => {
    switch (action?.toLowerCase()) {
      case 'allow':
      case 'permit':
        return 'success';
      case 'deny':
      case 'block':
        return 'error';
      default:
        return 'default';
    }
  };

  const getComplianceColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'compliant':
        return 'success';
      case 'non-compliant':
        return 'error';
      case 'warning':
        return 'warning';
      default:
        return 'default';
    }
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Normalized Rules
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Filters and Actions */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <TextField
              label="Search"
              variant="outlined"
              size="small"
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  handleSearch();
                }
              }}
              InputProps={{
                startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />,
              }}
              sx={{ minWidth: 200 }}
            />
            <Button
              variant="contained"
              size="small"
              onClick={handleSearch}
              startIcon={<SearchIcon />}
              sx={{ height: 40 }}
            >
              Search
            </Button>

            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Search Scope</InputLabel>
              <Select
                value={filters.search_scope}
                label="Search Scope"
                onChange={(e) => handleFilterChange('search_scope', e.target.value)}
              >
                <MenuItem value="all">All Fields</MenuItem>
                <MenuItem value="ip">IP Only</MenuItem>
                <MenuItem value="port">Port Only</MenuItem>
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 180 }}>
              <InputLabel>Search Field</InputLabel>
              <Select
                value={filters.search_fields}
                label="Search Field"
                onChange={(e) => handleFilterChange('search_fields', e.target.value)}
              >
                <MenuItem value="">Any Field</MenuItem>
                <MenuItem value="source_ip">Source IP</MenuItem>
                <MenuItem value="dest_ip">Destination IP</MenuItem>
                <MenuItem value="source_hostname">Source Hostname</MenuItem>
                <MenuItem value="dest_hostname">Destination Hostname</MenuItem>
                <MenuItem value="source_owner">Source Owner</MenuItem>
                <MenuItem value="dest_owner">Destination Owner</MenuItem>
                <MenuItem value="source_department">Source Department</MenuItem>
                <MenuItem value="dest_department">Destination Department</MenuItem>
                <MenuItem value="source_environment">Source Environment</MenuItem>
                <MenuItem value="dest_environment">Destination Environment</MenuItem>
                <MenuItem value="source_vlan_name">Source VLAN Name</MenuItem>
                <MenuItem value="dest_vlan_name">Destination VLAN Name</MenuItem>
                <MenuItem value="source_subnet">Source Subnet</MenuItem>
                <MenuItem value="dest_subnet">Destination Subnet</MenuItem>
                <MenuItem value="rule_name">Rule Name</MenuItem>
                <MenuItem value="service_name">Service Name</MenuItem>
                <MenuItem value="source_port">Source Port</MenuItem>
                <MenuItem value="dest_port">Destination Port</MenuItem>
                <MenuItem value="service_port">Service Port</MenuItem>
                <MenuItem value="notes">Notes</MenuItem>
                <MenuItem value="raw_text">Raw Text</MenuItem>
                <MenuItem value="rule_text">Rule Text</MenuItem>
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Source File</InputLabel>
              <Select
                value={filters.source_file}
                label="Source File"
                onChange={(e) => handleFilterChange('source_file', e.target.value)}
              >
                <MenuItem value="">All Files</MenuItem>
                {sourceFiles.map((file) => (
                  <MenuItem key={file} value={file}>{file}</MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Action</InputLabel>
              <Select
                value={filters.action}
                label="Action"
                onChange={(e) => handleFilterChange('action', e.target.value)}
              >
                <MenuItem value="">All Actions</MenuItem>
                <MenuItem value="Allow">Allow</MenuItem>
                <MenuItem value="Deny">Deny</MenuItem>
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Compliance</InputLabel>
              <Select
                value={filters.compliance_status}
                label="Compliance"
                onChange={(e) => handleFilterChange('compliance_status', e.target.value)}
              >
                <MenuItem value="">All Status</MenuItem>
                <MenuItem value="compliant">Compliant</MenuItem>
                <MenuItem value="non-compliant">Non-Compliant</MenuItem>
                <MenuItem value="warning">Warning</MenuItem>
              </Select>
            </FormControl>

          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchRules}
          >
            Refresh
          </Button>
          <Chip label={`${selectedIds.length} selected`} variant="outlined" sx={{ ml: 1 }} />
          <Button variant="outlined" onClick={() => setSelectedIds(rules.map(r => r.id))} disabled={rules.length === 0}>
            Select All (Page)
          </Button>
          <Button variant="outlined" onClick={() => setSelectedIds([])} disabled={selectedIds.length === 0}>
            Clear Selection
          </Button>
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
            disabled={selectedIds.length === 0}
            onClick={async () => {
              try {
                const resp = await fetch(`${API_BASE_URL}/api/normalized-rules/export`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ ids: selectedIds })
                });
                const blob = await resp.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'normalized_rules.csv';
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
              } catch (e) {
                console.error('Export failed', e);
              }
            }}
          >
            Export Selected (CSV)
          </Button>
          <Button
            variant="contained"
            color="primary"
            onClick={async () => {
              try {
                const sf = filters.source_file;
                if (!sf) {
                  setError('Select a Source File to normalize');
                  return;
                }
                const resp = await fetch(`${API_BASE_URL}/api/normalize-rules`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ source_file: sf, clear_existing: true, mode: 'one_to_one' })
                });
                const data = await resp.json();
                if (!resp.ok) throw new Error(data.error || 'Normalization failed');
                await fetchRules();
              } catch (e) {
                setError(e instanceof Error ? e.message : 'Normalization failed');
              }
            }}
            disabled={!filters.source_file}
          >
            Normalize Selected Source
          </Button>

            <Button
              variant="contained"
              color="error"
              startIcon={<DeleteSweepIcon />}
              onClick={handleBulkDelete}
              disabled={totalRules === 0}
            >
              Delete All Rules
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Rules Table */}
      <Card>
        <CardContent>
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
              <CircularProgress />
            </Box>
          ) : (
            <>
              <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h6">
                  {totalRules} Normalized Rules
                </Typography>
                <Pagination
                  count={totalPages}
                  page={page}
                  onChange={(_, newPage) => setPage(newPage)}
                  color="primary"
                />
              </Box>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell padding="checkbox">
                        <Checkbox
                          indeterminate={rules.length > 0 && rules.every(r => selectedIds.includes(r.id)) === false && rules.some(r => selectedIds.includes(r.id))}
                          checked={rules.length > 0 && rules.every(r => selectedIds.includes(r.id))}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedIds(rules.map(r => r.id));
                            } else {
                              setSelectedIds([]);
                            }
                          }}
                          inputProps={{ 'aria-label': 'select all rules on page' }}
                        />
                      </TableCell>
                      <TableCell>
                        <TableSortLabel
                          active={sortBy === 'id'}
                          direction={sortBy === 'id' ? sortOrder : 'asc'}
                          onClick={() => handleSort('id')}
                        >
                          ID
                        </TableSortLabel>
                      </TableCell>
                      <TableCell>Rule Name</TableCell>
                      <TableCell>Action</TableCell>
                      <TableCell>Protocol</TableCell>
                      <TableCell>Source</TableCell>
                      <TableCell>Src VLAN</TableCell>
                      <TableCell>Destination</TableCell>
                      <TableCell>Dst VLAN</TableCell>
                      <TableCell>Port</TableCell>
                      <TableCell>Service</TableCell>
                      <TableCell>Hits</TableCell>
                      <TableCell>Compliance</TableCell>
                      <TableCell>Source File</TableCell>
                      <TableCell>
                        <TableSortLabel
                          active={sortBy === 'created_at'}
                          direction={sortBy === 'created_at' ? sortOrder : 'asc'}
                          onClick={() => handleSort('created_at')}
                        >
                          Created
                        </TableSortLabel>
                      </TableCell>
                      <TableCell align="center">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rules.map((rule) => (
                      <TableRow key={rule.id} hover>
                        <TableCell padding="checkbox">
                          <Checkbox
                            checked={selectedIds.includes(rule.id)}
                            onChange={(e) => {
                              setSelectedIds(prev => e.target.checked ? [...prev, rule.id] : prev.filter(id => id !== rule.id));
                            }}
                            inputProps={{ 'aria-label': `select rule ${rule.id}` }}
                          />
                        </TableCell>
                        <TableCell>{rule.id}</TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {getRuleName(rule)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.action}
                            color={getActionColor(rule.action) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>{rule.protocol}</TableCell>
                        <TableCell>
                        <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {rule.source_ip_with_zone || rule.source_ip}
                        </Typography>
                      </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {rule.source_vlan_name ? (rule.source_location ? `${rule.source_vlan_name} (${rule.source_location})` : rule.source_vlan_name) : (rule.source_subnet || '—')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                        <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {rule.dest_ip_with_zone || rule.dest_ip}
                        </Typography>
                      </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {rule.dest_vlan_name ? (rule.dest_location ? `${rule.dest_vlan_name} (${rule.dest_location})` : rule.dest_vlan_name) : (rule.dest_subnet || '—')}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <PortsDisplay protocol={rule.protocol} destPort={getAggregatedPorts(rule, rules)} maxVisible={3} />
                        </TableCell>
                        <TableCell>{rule.service_name || 'N/A'}</TableCell>
                        <TableCell>
                          {rule.hit_count !== null && rule.hit_count !== undefined ? rule.hit_count.toLocaleString() : '—'}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.compliance_status}
                            color={getComplianceColor(rule.compliance_status) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>{rule.source_file}</TableCell>
                        <TableCell>
                          {new Date(rule.created_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell align="center">
                          <IconButton
                            size="small"
                            onClick={(e) => handleMenuOpen(e, rule)}
                          >
                            <MoreVertIcon />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {totalPages > 1 && (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
                  <Pagination
                    count={totalPages}
                    page={page}
                    onChange={(_, newPage) => setPage(newPage)}
                    color="primary"
                  />
                </Box>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
      <MenuItem onClick={handleViewRule}>
        <VisibilityIcon sx={{ mr: 1 }} />
        View Details
      </MenuItem>
      <MenuItem onClick={async () => {
        try {
          if (!selectedRule) return;
          const resp = await fetch(`${API_BASE_URL}/api/normalized-rules/export`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: [selectedRule.id] })
          });
          const blob = await resp.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `normalized_rule_${selectedRule.id}.csv`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(url);
        } catch (e) {
          console.error('Export failed', e);
        } finally {
          handleMenuClose();
        }
      }}>
        <DownloadIcon sx={{ mr: 1 }} />
        Export as CSV
      </MenuItem>
        <MenuItem onClick={() => {
          if (!selectedRule) return;
          setEditData({
            action: selectedRule.action || '',
            protocol: selectedRule.protocol || '',
            source_ip: selectedRule.source_ip || '',
            dest_ip: selectedRule.dest_ip || '',
            dest_port: selectedRule.dest_port || '',
            service_name: selectedRule.service_name || '',
            compliance_status: selectedRule.compliance_status || '',
            review_status: 'pending',
            notes: ''
          });
          setEditDialogOpen(true);
          handleMenuClose();
        }}>
          <MoreVertIcon sx={{ mr: 1 }} />
          Edit Rule
        </MenuItem>
        <MenuItem onClick={async () => {
          try {
            if (!selectedRule) return;
            const sf = selectedRule.source_file;
            const resp = await fetch(`${API_BASE_URL}/api/normalize-rules`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ source_file: sf, clear_existing: true, mode: 'one_to_one' })
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || 'Normalization failed');
            await fetchRules();
          } catch (err) {
            console.error(err);
          } finally {
            handleMenuClose();
          }
        }}>
          <RefreshIcon sx={{ mr: 1 }} />
          Re-normalize This File
        </MenuItem>
        <MenuItem onClick={handleDeleteRule} sx={{ color: 'error.main' }}>
          <DeleteIcon sx={{ mr: 1 }} />
          Delete Rule
        </MenuItem>
      </Menu>

      {/* View Rule Dialog */}
      <Dialog open={viewDialogOpen} onClose={() => setViewDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Rule Details</DialogTitle>
        <DialogContent>
          {selectedRule && (
            <Box sx={{ mt: 1, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 2, '& .MuiTypography-root': { overflowWrap: 'anywhere' } }}>
              <Typography sx={{ gridColumn: '1 / -1' }}><strong>ID:</strong> {selectedRule.id}</Typography>
              <Typography sx={{ gridColumn: '1 / -1' }}><strong>Rule Name:</strong> {getRuleName(selectedRule)}</Typography>
              <Typography><strong>Action:</strong> {selectedRule.action}</Typography>
              <Typography><strong>Protocol:</strong> {selectedRule.protocol}</Typography>
              <Typography><strong>Source Zone:</strong> {(selectedRule as any).source_zone || 'N/A'}</Typography>
              <Typography><strong>Destination Zone:</strong> {(selectedRule as any).dest_zone || 'N/A'}</Typography>
              <Typography><strong>Application:</strong> {(selectedRule as any).application || 'N/A'}</Typography>
              <Typography><strong>Source IP:</strong> {selectedRule.source_ip}</Typography>
              <Typography><strong>Source VLAN:</strong> {selectedRule.source_vlan_name || selectedRule.source_subnet || 'N/A'}</Typography>
              <Typography><strong>Source Location:</strong> {selectedRule.source_location || 'N/A'}</Typography>
              <Typography><strong>Destination IP:</strong> {selectedRule.dest_ip}</Typography>
              <Typography><strong>Destination VLAN:</strong> {selectedRule.dest_vlan_name || selectedRule.dest_subnet || 'N/A'}</Typography>
              <Typography><strong>Destination Location:</strong> {selectedRule.dest_location || 'N/A'}</Typography>
              <Typography><strong>Destination Port:</strong> {selectedRule.dest_port}</Typography>
              <Typography><strong>Service:</strong> {selectedRule.service_name || 'N/A'}</Typography>
              <Typography><strong>Compliance:</strong> {selectedRule.compliance_status}</Typography>
              <Typography><strong>Source File:</strong> {selectedRule.source_file}</Typography>
              <Typography><strong>Created:</strong> {new Date(selectedRule.created_at).toLocaleString()}</Typography>

              {selectedRule && (
                <Box sx={{ gridColumn: '1 / -1', mt: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Raw Rule</Typography>
                  {selectedRule.raw_rule_name && (
                    <Typography><strong>Raw Rule Name:</strong> {selectedRule.raw_rule_name}</Typography>
                  )}
                  {selectedRule.raw_text && (
                    <Box sx={{ mt: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1 }}>
                      <Typography variant="subtitle2">Raw Text</Typography>
                      <Box component="pre" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', m: 0 }}>{selectedRule.raw_text}</Box>
                    </Box>
                  )}
                  {selectedRule.rule_text && (
                    <Box sx={{ mt: 1, p: 1, bgcolor: 'grey.100', borderRadius: 1 }}>
                      <Typography variant="subtitle2">Parsed Text</Typography>
                      <Box component="pre" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', m: 0 }}>{selectedRule.rule_text}</Box>
                    </Box>
                  )}
                  {selectedRule.raw_data && (
                    <Box sx={{ mt: 1 }}>
                      <TableContainer component={Paper}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Field</TableCell>
                              <TableCell>Value</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            <TableRow>
                              <TableCell>Vendor</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).vendor || ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell>ACL Name</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).acl_name || ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell>Line Number in ACL</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).line_number_in_acl ?? ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell>Source (raw)</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).source || ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell>Destination (raw)</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).destination || ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell>Source Port (raw)</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).source_port || ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell>Destination Port (raw)</TableCell>
                              <TableCell sx={{ wordBreak: 'break-word' }}>{(selectedRule.raw_data as any).dest_port || ''}</TableCell>
                            </TableRow>
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  )}
                  {!selectedRule.raw_text && !selectedRule.rule_text && !selectedRule.raw_data && (
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                      No raw rule details available for this entry.
                    </Typography>
                  )}
                </Box>
              )}

              {/* Custom Fields */}
              <Box sx={{ gridColumn: '1 / -1', mt: 2 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Custom Fields</Typography>
                {(() => {
                  try {
                    const cf = (selectedRule as any).custom_fields_data;
                    const obj = typeof cf === 'string' ? JSON.parse(cf) : (cf || {});
                    const entries = Object.entries(obj);
                    if (!entries.length) return <Alert severity="info">No custom fields</Alert>;
                    return (
                      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 2, mt: 1 }}>
                        {entries.map(([k, v]) => (
                          <Box key={k}>
                            <Typography variant="subtitle2" color="text.secondary">{k}</Typography>
                            <Typography sx={{ wordBreak: 'break-word' }}>{String(v)}</Typography>
                          </Box>
                        ))}
                      </Box>
                    );
                  } catch (e) {
                    return <Alert severity="warning">Failed to parse custom fields</Alert>;
                  }
                })()}
              </Box>

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt: 2, fontWeight: 600 }}>Source CMDB</Typography>
              {selectedRule.cmdb_available_fields?.includes('hostname') && (<Typography><strong>Hostname:</strong> {selectedRule.source_hostname || ''}</Typography>)}
              {selectedRule.cmdb_available_fields?.includes('owner') && (
                <Box>
                  <Typography><strong>Owner:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.source_cmdb_matches || []).map(m => m.owner).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('department') && (<Typography><strong>Department:</strong> {selectedRule.source_department || ''}</Typography>)}
              {selectedRule.cmdb_available_fields?.includes('environment') && (
                <Box>
                  <Typography><strong>Environment:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.source_cmdb_matches || []).map(m => m.environment).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('pcidss_asset_category') && (
                <Box>
                  <Typography><strong>PCI DSS Categories:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.source_cmdb_matches || []).map(m => m.pcidss_asset_category).filter(Boolean))).map((cat, i) => (
                      <Chip key={i} label={cat} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('application_name') && (<Typography><strong>Application:</strong> {selectedRule.source_cmdb_matches?.[0]?.application || ''}</Typography>)}
              {selectedRule.cmdb_available_fields?.includes('asset_type') && (
                <Box>
                  <Typography><strong>Asset Type:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.source_cmdb_matches || []).map(m => m.asset_type).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('operating_system') && (
                <Box>
                  <Typography><strong>OS:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.source_cmdb_matches || []).map(m => m.operating_system).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('model') && (
                <Box>
                  <Typography><strong>Model:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.source_cmdb_matches || []).map(m => m.model).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              <Typography><strong>VLAN ID:</strong> {selectedRule.source_vlan_id ?? ''}</Typography>
              <Typography><strong>VLAN Name:</strong> {selectedRule.source_vlan_name || ''}</Typography>
              <Typography><strong>Subnet:</strong> {selectedRule.source_subnet || ''}</Typography>
              {Array.isArray(selectedRule.source_cmdb_matches) && selectedRule.source_cmdb_matches.length > 0 && (
                <Box sx={{ gridColumn: '1 / -1', mt: 1 }}>
                  <Typography sx={{ fontWeight: 600 }}>Source Matches ({selectedRule.source_cmdb_matches.length})</Typography>
                  <TableContainer component={Paper} sx={{ mt: 1, gridColumn: '1 / -1', maxWidth: '100%' }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>IP</TableCell>
                          <TableCell>Hostname</TableCell>
                          <TableCell>Owner</TableCell>
                          <TableCell>Department</TableCell>
                          <TableCell>Environment</TableCell>
                          <TableCell>PCI DSS</TableCell>
                          <TableCell>Application</TableCell>
                          <TableCell>Asset</TableCell>
                          <TableCell>OS</TableCell>
                          <TableCell>Model</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {selectedRule.source_cmdb_matches.slice(0, 50).map((m, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.ip_address || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.hostname || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.owner || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.department || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.environment || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.pcidss_asset_category || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.application || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.asset_type || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.operating_system || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.model || ''}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt: 2, fontWeight: 600 }}>Destination CMDB</Typography>
              {selectedRule.cmdb_available_fields?.includes('hostname') && (<Typography><strong>Hostname:</strong> {selectedRule.dest_hostname || ''}</Typography>)}
              {selectedRule.cmdb_available_fields?.includes('owner') && (
                <Box>
                  <Typography><strong>Owner:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.dest_cmdb_matches || []).map(m => m.owner).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('department') && (<Typography><strong>Department:</strong> {selectedRule.dest_department || ''}</Typography>)}
              {selectedRule.cmdb_available_fields?.includes('environment') && (
                <Box>
                  <Typography><strong>Environment:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.dest_cmdb_matches || []).map(m => m.environment).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('pcidss_asset_category') && (
                <Box>
                  <Typography><strong>PCI DSS Categories:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.dest_cmdb_matches || []).map(m => m.pcidss_asset_category).filter(Boolean))).map((cat, i) => (
                      <Chip key={i} label={cat} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('application_name') && (<Typography><strong>Application:</strong> {selectedRule.dest_cmdb_matches?.[0]?.application || ''}</Typography>)}
              {selectedRule.cmdb_available_fields?.includes('asset_type') && (
                <Box>
                  <Typography><strong>Asset Type:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.dest_cmdb_matches || []).map(m => m.asset_type).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('operating_system') && (
                <Box>
                  <Typography><strong>OS:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.dest_cmdb_matches || []).map(m => m.operating_system).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              {selectedRule.cmdb_available_fields?.includes('model') && (
                <Box>
                  <Typography><strong>Model:</strong></Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {Array.from(new Set((selectedRule.dest_cmdb_matches || []).map(m => m.model).filter(Boolean))).map((v, i) => (
                      <Chip key={i} label={v as string} size="small" />
                    ))}
                  </Box>
                </Box>
              )}
              <Typography><strong>VLAN ID:</strong> {selectedRule.dest_vlan_id ?? ''}</Typography>
              <Typography><strong>VLAN Name:</strong> {selectedRule.dest_vlan_name || ''}</Typography>
              <Typography><strong>Subnet:</strong> {selectedRule.dest_subnet || ''}</Typography>
              {Array.isArray(selectedRule.dest_cmdb_matches) && selectedRule.dest_cmdb_matches.length > 0 && (
                <Box sx={{ gridColumn: '1 / -1', mt: 1 }}>
                  <Typography sx={{ fontWeight: 600 }}>Destination Matches ({selectedRule.dest_cmdb_matches.length})</Typography>
                  <TableContainer component={Paper} sx={{ mt: 1, gridColumn: '1 / -1', maxWidth: '100%' }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>IP</TableCell>
                          <TableCell>Hostname</TableCell>
                          <TableCell>Owner</TableCell>
                          <TableCell>Department</TableCell>
                          <TableCell>Environment</TableCell>
                          <TableCell>PCI DSS</TableCell>
                          <TableCell>Application</TableCell>
                          <TableCell>Asset</TableCell>
                          <TableCell>OS</TableCell>
                          <TableCell>Model</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {selectedRule.dest_cmdb_matches.slice(0, 50).map((m, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.ip_address || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.hostname || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.owner || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.department || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.environment || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.pcidss_asset_category || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.application || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.asset_type || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.operating_system || ''}</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{m.model || ''}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              <Typography sx={{ gridColumn: '1 / -1' }}><strong>Ports:</strong> <PortsDisplay protocol={selectedRule.protocol} destPort={selectedRule.dest_port} maxVisible={10} /></Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Edit Rule Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Edit Normalized Rule</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <TextField label="Action" value={editData.action || ''} onChange={(e)=>setEditData({...editData, action:e.target.value})} />
            <TextField label="Protocol" value={editData.protocol || ''} onChange={(e)=>setEditData({...editData, protocol:e.target.value})} />
            <TextField label="Source IP" value={editData.source_ip || ''} onChange={(e)=>setEditData({...editData, source_ip:e.target.value})} />
            <TextField label="Destination IP" value={editData.dest_ip || ''} onChange={(e)=>setEditData({...editData, dest_ip:e.target.value})} />
            <TextField label="Destination Port" value={editData.dest_port || ''} onChange={(e)=>setEditData({...editData, dest_port:e.target.value})} />
            <TextField label="Service Name" value={editData.service_name || ''} onChange={(e)=>setEditData({...editData, service_name:e.target.value})} />
            <TextField label="Compliance Status" value={editData.compliance_status || ''} onChange={(e)=>setEditData({...editData, compliance_status:e.target.value})} />
            <TextField label="Review Status" value={editData.review_status || ''} onChange={(e)=>setEditData({...editData, review_status:e.target.value})} />
          </Box>
          <TextField label="Notes" value={editData.notes || ''} onChange={(e)=>setEditData({...editData, notes:e.target.value})} fullWidth multiline rows={3} sx={{ mt: 2 }} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={async ()=>{
            try{
              if(!selectedRule) return;
              const resp = await fetch(`${API_BASE_URL}/api/normalized-rules/${selectedRule.id}`,{
                method:'PUT',
                headers:{'Content-Type':'application/json'},
                body: JSON.stringify(editData)
              });
              if(!resp.ok){
                const e=await resp.json();
                throw new Error(e.error||'Update failed');
              }
              setEditDialogOpen(false);
              await fetchRules();
            }catch(err){
              console.error(err);
              setSnackbar({open:true,severity:'error',message: (err instanceof Error? err.message:'Update failed')});
            }
          }}>Save</Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete rule "{selectedRule?.id}"?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={confirmDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Bulk Delete Confirmation Dialog */}
      <Dialog open={bulkDeleteDialogOpen} onClose={() => setBulkDeleteDialogOpen(false)}>
        <DialogTitle>Confirm Delete All Rules</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete ALL {totalRules} normalized rules? This action cannot be undone.
          </Typography>
          <Alert severity="warning" sx={{ mt: 2 }}>
            This will soft-delete all normalized rules. They can be restored by re-running normalization.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBulkDeleteDialogOpen(false)} disabled={bulkDeleting}>
            Cancel
          </Button>
          <Button 
            onClick={confirmBulkDelete} 
            color="error" 
            variant="contained"
            disabled={bulkDeleting}
            startIcon={bulkDeleting ? <CircularProgress size={20} /> : <DeleteSweepIcon />}
          >
            {bulkDeleting ? 'Deleting...' : 'Delete All Rules'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert 
          onClose={() => setSnackbar({ ...snackbar, open: false })} 
          severity={snackbar.severity}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default NormalizedRules;
