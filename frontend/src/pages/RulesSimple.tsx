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
  Checkbox,
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
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  DeleteSweep as DeleteSweepIcon,
  MoreVert as MoreVertIcon,
} from '@mui/icons-material';
import PortsDisplay from '../components/PortsDisplay';
import PortWithService from '../components/PortWithService';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

// Helper function to get a displayable rule name
const getRawRuleName = (rule: RawRule): string => {
  if (rule.rule_name && rule.rule_name.trim().length > 0) {
    return rule.rule_name;
  }
  return `Rule ${rule.id}`;
};

interface RawRule {
  id: number;
  source_file: string;
  rule_type: string;
  action: string;
  protocol: string;
  source: string;
  source_port: string;
  destination: string;
  dest_port: string;
  rule_name: string;
  rule_text: string;
  raw_text: string;
  file_line_number?: number;
  vendor?: string;
  acl_name?: string;
  line_number_in_acl?: number;
  created_at: string;
  updated_at: string;
  raw_data?: Record<string, any>;
}

interface FilterState {
  search: string;
  source_file: string;
  rule_type: string;
  action: string;
  protocol: string;
  search_scope: string;
  search_fields: string;
}

const RulesSimple: React.FC = () => {
  const [rules, setRules] = useState<RawRule[]>([]);
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
    rule_type: '',
    action: '',
    protocol: '',
    search_scope: 'all',
    search_fields: '',
  });
  // Applied filters state for search execution
  const [appliedFilters, setAppliedFilters] = useState<FilterState>({
    search: '',
    source_file: '',
    rule_type: '',
    action: '',
    protocol: '',
    search_scope: 'all',
    search_fields: '',
  });
  const [sortBy, setSortBy] = useState('id');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Dialog states
  const [selectedRule, setSelectedRule] = useState<RawRule | null>(null);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteAllDialogOpen, setDeleteAllDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);

  // Edit form state
  const [editFormData, setEditFormData] = useState<Partial<RawRule>>({});
  const [editFormErrors, setEditFormErrors] = useState<{[key: string]: string}>({});
  const [isSaving, setIsSaving] = useState(false);

  // Utility functions

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, rule: RawRule) => {
    setAnchorEl(event.currentTarget);
    setSelectedRule(rule);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleViewRule = () => {
    setViewDialogOpen(true);
    handleMenuClose();
  };

  const handleEditRule = () => {
    if (selectedRule) {
      setEditFormData({
        rule_name: selectedRule.rule_name || '',
        action: selectedRule.action || '',
        protocol: selectedRule.protocol || '',
        source: selectedRule.source || '',
        destination: selectedRule.destination || '',
        source_port: selectedRule.source_port || '',
        dest_port: selectedRule.dest_port || '',
        rule_text: selectedRule.rule_text || '',
        acl_name: selectedRule.acl_name || ''
      });
      setEditFormErrors({});
      setEditDialogOpen(true);
    }
    handleMenuClose();
  };

  const handleDeleteRule = () => {
    setDeleteDialogOpen(true);
    handleMenuClose();
  };

  const confirmDelete = async () => {
    if (!selectedRule) return;
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/rules/${selectedRule.id}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        await fetchRules(); // Refresh the list
        setDeleteDialogOpen(false);
        setSelectedRule(null);
      } else {
        console.error('Failed to delete rule');
      }
    } catch (err) {
      console.error('Error deleting rule:', err);
    }
  };

  const handleDeleteAll = () => {
    setDeleteAllDialogOpen(true);
  };

  const confirmDeleteAll = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/rules/bulk-delete`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          delete_all: true
        }),
      });
      
      if (response.ok) {
        await fetchRules(); // Refresh the list
        setDeleteAllDialogOpen(false);
      } else {
        console.error('Failed to delete all rules');
      }
    } catch (err) {
      console.error('Error deleting all rules:', err);
    }
  };

  // Edit form handling functions
  const handleEditFormChange = (field: string, value: string) => {
    setEditFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Clear error for this field when user starts typing
    if (editFormErrors[field]) {
      setEditFormErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  };

  const validateEditForm = (): boolean => {
    const errors: {[key: string]: string} = {};
    
    if (!editFormData.rule_name?.trim()) {
      errors.rule_name = 'Rule name is required';
    }
    
    if (!editFormData.action?.trim()) {
      errors.action = 'Action is required';
    }
    
    if (!editFormData.protocol?.trim()) {
      errors.protocol = 'Protocol is required';
    }
    
    setEditFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSaveEdit = async () => {
    if (!selectedRule || !validateEditForm()) {
      return;
    }

    setIsSaving(true);
    try {
      const response = await fetch(`http://localhost:5001/api/rules/${selectedRule.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(editFormData),
      });

      if (response.ok) {
        await fetchRules(); // Refresh the list
        setEditDialogOpen(false);
        setSelectedRule(null);
        setEditFormData({});
      } else {
        const errorData = await response.json();
        console.error('Failed to update rule:', errorData.error);
      }
    } catch (err) {
      console.error('Error updating rule:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleCancelEdit = () => {
    setEditDialogOpen(false);
    setEditFormData({});
    setEditFormErrors({});
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

  // Fetch rules
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

      const response = await fetch(`${API_BASE_URL}/api/rules?${params}`);
      if (!response.ok) {
        throw new Error('Failed to fetch rules');
      }

      const data = await response.json();
      setRules(data.rules || []);
      setTotalPages(data.pages || 1);
      setTotalRules(data.total || 0);
      setSelectedIds([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch rules');
    } finally {
      setLoading(false);
    }
  }, [page, perPage, sortBy, sortOrder, appliedFilters]);

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

  if (loading) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
        <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
          <CircularProgress />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Firewall Rules ({totalRules} rules)
      </Typography>

      {error && (
        <Box mb={2}>
          <Typography color="error">{error}</Typography>
        </Box>
      )}

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Filters
          </Typography>
          <Box display="flex" gap={2} flexWrap="wrap" alignItems="center">
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
                <MenuItem value="source">Source</MenuItem>
                <MenuItem value="destination">Destination</MenuItem>
                <MenuItem value="rule_text">Rule Text</MenuItem>
                <MenuItem value="raw_text">Raw Text</MenuItem>
                <MenuItem value="rule_name">Rule Name</MenuItem>
                <MenuItem value="action">Action</MenuItem>
                <MenuItem value="protocol">Protocol</MenuItem>
                <MenuItem value="acl_name">ACL Name</MenuItem>
                <MenuItem value="vendor">Vendor</MenuItem>
                <MenuItem value="source_port">Source Port</MenuItem>
                <MenuItem value="dest_port">Destination Port</MenuItem>
                <MenuItem value="source_file">Source File</MenuItem>
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
                <MenuItem value="permit">Permit</MenuItem>
                <MenuItem value="deny">Deny</MenuItem>
              </Select>
            </FormControl>

          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchRules}
          >
            Refresh
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
                if (!resp.ok) {
                  throw new Error(data.error || 'Normalization failed');
                }
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
              variant="outlined"
              color="error"
              startIcon={<DeleteSweepIcon />}
              onClick={handleDeleteAll}
              disabled={totalRules === 0}
            >
              Delete All
            </Button>
            <Chip label={`${selectedIds.length} selected`} variant="outlined" sx={{ ml: 1 }} />
            <Button
              variant="outlined"
              onClick={() => {
                const ids = rules.map(r => r.id);
                setSelectedIds(ids);
              }}
              disabled={rules.length === 0}
            >
              Select All (Page)
            </Button>
            <Button
              variant="outlined"
              onClick={() => setSelectedIds([])}
              disabled={selectedIds.length === 0}
            >
              Clear Selection
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={async () => {
                if (selectedIds.length === 0) return;
                try {
                  const resp = await fetch(`${API_BASE_URL}/api/rules/bulk-delete`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ rule_ids: selectedIds })
                  });
                  const d = await resp.json();
                  if (!resp.ok) throw new Error(d.error || 'Bulk delete failed');
                  await fetchRules();
                } catch (e) {
                  console.error(e);
                }
              }}
              disabled={selectedIds.length === 0}
            >
              Delete Selected
            </Button>
            <Button
              variant="contained"
              onClick={async () => {
                if (selectedIds.length === 0) return;
                const selected = rules.filter(r => selectedIds.includes(r.id));
                const files = Array.from(new Set(selected.map(r => r.source_file).filter(Boolean)));
                try {
                  for (const sf of files) {
                    const resp = await fetch(`${API_BASE_URL}/api/normalize-rules`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ source_file: sf, clear_existing: true })
                    });
                    const d = await resp.json();
                    if (!resp.ok) throw new Error(d.error || `Normalization failed for ${sf}`);
                  }
                } catch (e) {
                  console.error(e);
                }
              }}
              disabled={selectedIds.length === 0}
            >
              Normalize Selected Files
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Rules Table */}
      <Card>
        <CardContent>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={selectedIds.length === rules.length && rules.length > 0}
                      indeterminate={selectedIds.length > 0 && selectedIds.length < rules.length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedIds(rules.map(r => r.id));
                        } else {
                          setSelectedIds([]);
                        }
                      }}
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
                  <TableCell>Ports</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Destination</TableCell>
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
                          if (e.target.checked) {
                            setSelectedIds(prev => [...prev, rule.id]);
                          } else {
                            setSelectedIds(prev => prev.filter(id => id !== rule.id));
                          }
                        }}
                      />
                    </TableCell>
                    <TableCell>{rule.id}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                        {getRawRuleName(rule)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.action}
                        color={getActionColor(rule.action) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{rule.protocol || 'N/A'}</TableCell>
                    <TableCell>
                      <PortsDisplay protocol={rule.protocol} destPort={rule.dest_port} maxVisible={3} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {rule.source || 'N/A'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {rule.destination || 'N/A'}
                      </Typography>
                    </TableCell>
                    <TableCell>{rule.source_file}</TableCell>
                    <TableCell>
                      {new Date(rule.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="center">
                      <Tooltip title="Actions">
                        <IconButton
                          size="small"
                          onClick={(e) => handleMenuOpen(e, rule)}
                        >
                          <MoreVertIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Pagination */}
          <Box display="flex" justifyContent="center" mt={3}>
            <Pagination
              count={totalPages}
              page={page}
              onChange={(_, newPage) => setPage(newPage)}
              color="primary"
            />
          </Box>
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
            const sf = selectedRule.source_file;
            const resp = await fetch(`${API_BASE_URL}/api/normalize-rules`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ source_file: sf, clear_existing: true, mode: 'one_to_one' })
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || 'Normalization failed');
          } catch (err) {
            console.error(err);
          } finally {
            handleMenuClose();
          }
        }}>
          <RefreshIcon sx={{ mr: 1 }} />
          Normalize This File
        </MenuItem>
        <MenuItem onClick={handleEditRule}>
          <EditIcon sx={{ mr: 1 }} />
          Edit Rule
        </MenuItem>
        <MenuItem onClick={handleDeleteRule} sx={{ color: 'error.main' }}>
          <DeleteIcon sx={{ mr: 1 }} />
          Delete Rule
        </MenuItem>
      </Menu>

      {/* View Rule Dialog */}
      <Dialog
        open={viewDialogOpen}
        onClose={() => setViewDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Rule Details</DialogTitle>
        <DialogContent>
          {selectedRule && (
            <Box sx={{ mt: 1 }}>
              <Typography variant="h6" gutterBottom>
                {getRawRuleName(selectedRule)}
              </Typography>
              
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mt: 2 }}>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">ID</Typography>
                  <Typography>{selectedRule.id}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Action</Typography>
                  <Chip label={selectedRule.action} size="small" />
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Protocol</Typography>
                  <Typography>{selectedRule.protocol || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Source Zone</Typography>
                  <Typography>{(selectedRule as any).source_zone || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Destination Zone</Typography>
                  <Typography>{(selectedRule as any).dest_zone || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Application</Typography>
                  <Typography>{(selectedRule as any).application || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Ports</Typography>
                  <PortsDisplay protocol={selectedRule.protocol} destPort={selectedRule.dest_port} maxVisible={10} />
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Source</Typography>
                  <Typography>{selectedRule.source || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Destination</Typography>
                  <Typography>{selectedRule.destination || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Source Port</Typography>
                  {selectedRule.source_port ? (
                    <PortWithService port={selectedRule.source_port} variant="text" />
                  ) : (
                    <Typography>N/A</Typography>
                  )}
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Destination Port</Typography>
                  {selectedRule.dest_port ? (
                    <PortWithService port={selectedRule.dest_port} variant="text" />
                  ) : (
                    <Typography>N/A</Typography>
                  )}
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Source File</Typography>
                  <Typography>{selectedRule.source_file}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Rule Type</Typography>
                  <Typography>{selectedRule.rule_type || 'N/A'}</Typography>
                </Box>
              </Box>

              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" color="text.secondary">Rule Text</Typography>
                <Paper sx={{ p: 2, mt: 1, backgroundColor: 'grey.50' }}>
                  {/* Render full uploaded columns with names if available */}
                  {selectedRule.raw_data ? (
                    Object.entries(selectedRule.raw_data).map(([key, value]) => (
                      <Typography key={key} variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                        {key}: {value === null || value === undefined || (typeof value === 'string' && value.trim() === '') ? 'N/A' : String(value)}
                      </Typography>
                    ))
                  ) : (
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                      {selectedRule.rule_text || selectedRule.raw_text || 'N/A'}
                    </Typography>
                  )}
                </Paper>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Edit Rule Dialog */}
      <Dialog
        open={editDialogOpen}
        onClose={handleCancelEdit}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Edit Rule</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <TextField
              label="Rule Name"
              value={editFormData.rule_name || ''}
              onChange={(e) => handleEditFormChange('rule_name', e.target.value)}
              error={!!editFormErrors.rule_name}
              helperText={editFormErrors.rule_name}
              fullWidth
            />
            
            <FormControl fullWidth error={!!editFormErrors.action}>
              <InputLabel>Action</InputLabel>
              <Select
                value={editFormData.action || ''}
                onChange={(e) => handleEditFormChange('action', e.target.value)}
                label="Action"
              >
                <MenuItem value="permit">Permit</MenuItem>
                <MenuItem value="deny">Deny</MenuItem>
              </Select>
              {editFormErrors.action && (
                <Typography variant="caption" color="error" sx={{ mt: 0.5, ml: 1.5 }}>
                  {editFormErrors.action}
                </Typography>
              )}
            </FormControl>

            <TextField
              label="Protocol"
              value={editFormData.protocol || ''}
              onChange={(e) => handleEditFormChange('protocol', e.target.value)}
              error={!!editFormErrors.protocol}
              helperText={editFormErrors.protocol}
              fullWidth
            />

            <TextField
              label="ACL Name"
              value={editFormData.acl_name || ''}
              onChange={(e) => handleEditFormChange('acl_name', e.target.value)}
              fullWidth
            />

            <TextField
              label="Source"
              value={editFormData.source || ''}
              onChange={(e) => handleEditFormChange('source', e.target.value)}
              fullWidth
            />

            <TextField
              label="Destination"
              value={editFormData.destination || ''}
              onChange={(e) => handleEditFormChange('destination', e.target.value)}
              fullWidth
            />

            <TextField
              label="Source Port"
              value={editFormData.source_port || ''}
              onChange={(e) => handleEditFormChange('source_port', e.target.value)}
              fullWidth
            />

            <TextField
              label="Destination Port"
              value={editFormData.dest_port || ''}
              onChange={(e) => handleEditFormChange('dest_port', e.target.value)}
              fullWidth
            />
          </Box>

          <TextField
            label="Rule Text"
            value={editFormData.rule_text || ''}
            onChange={(e) => handleEditFormChange('rule_text', e.target.value)}
            multiline
            rows={4}
            fullWidth
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelEdit} disabled={isSaving}>
            Cancel
          </Button>
          <Button 
            onClick={handleSaveEdit} 
            variant="contained" 
            disabled={isSaving}
          >
            {isSaving ? <CircularProgress size={20} /> : 'Save Changes'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete rule "{selectedRule?.rule_name || selectedRule?.id}"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={confirmDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete All Confirmation Dialog */}
      <Dialog open={deleteAllDialogOpen} onClose={() => setDeleteAllDialogOpen(false)}>
        <DialogTitle>Confirm Delete All</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete ALL raw firewall rules?
            This will permanently remove all {totalRules} rules from the database.
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteAllDialogOpen(false)}>Cancel</Button>
          <Button onClick={confirmDeleteAll} color="error" variant="contained">
            Delete All
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default RulesSimple;
