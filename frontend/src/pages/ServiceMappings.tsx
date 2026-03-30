import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  IconButton,
  Alert,
  Snackbar,
  FormControlLabel,
  Switch,
  Card,
  CardContent,
  Tooltip,
  Grid,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';

interface ServiceMapping {
  id: number;
  service_name: string;
  port_number: number;
  protocol: string;
  description: string;
  category: string;
  is_well_known: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface ServiceMappingFormData {
  service_name: string;
  port_number: string;
  protocol: string;
  description: string;
  category: string;
  is_well_known: boolean;
  is_active: boolean;
}

const ServiceMappings: React.FC = () => {
  const [mappings, setMappings] = useState<ServiceMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [wellKnownFilter, setWellKnownFilter] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  const [categories, setCategories] = useState<string[]>([]);
  const [protocols, setProtocols] = useState<string[]>([]);
  
  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [editingMapping, setEditingMapping] = useState<ServiceMapping | null>(null);
  const [formData, setFormData] = useState<ServiceMappingFormData>({
    service_name: '',
    port_number: '',
    protocol: 'tcp',
    description: '',
    category: '',
    is_well_known: false,
    is_active: true,
  });
  
  // Notification states
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });

  const fetchMappings = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: (page + 1).toString(),
        per_page: rowsPerPage.toString(),
      });
      
      if (searchTerm) params.append('search', searchTerm);
      if (categoryFilter) params.append('category', categoryFilter);
      if (protocolFilter) params.append('protocol', protocolFilter);
      if (wellKnownFilter) params.append('well_known', wellKnownFilter);
      if (activeFilter) params.append('active', activeFilter);

      const response = await fetch(`http://localhost:5001/api/service-mappings?${params}`);
      const data = await response.json();
      
      if (response.ok) {
        setMappings(data.mappings);
        setTotalCount(data.pagination.total);
        setCategories(data.filters.categories);
        setProtocols(data.filters.protocols);
      } else {
        throw new Error(data.error || 'Failed to fetch service mappings');
      }
    } catch (error) {
      console.error('Error fetching service mappings:', error);
      setSnackbar({ open: true, message: 'Failed to fetch service mappings', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMappings();
  }, [page, rowsPerPage, searchTerm, categoryFilter, protocolFilter, wellKnownFilter, activeFilter]);

  const handleOpenDialog = (mapping?: ServiceMapping) => {
    if (mapping) {
      setEditingMapping(mapping);
      setFormData({
        service_name: mapping.service_name,
        port_number: mapping.port_number.toString(),
        protocol: mapping.protocol,
        description: mapping.description,
        category: mapping.category,
        is_well_known: mapping.is_well_known,
        is_active: mapping.is_active,
      });
    } else {
      setEditingMapping(null);
      setFormData({
        service_name: '',
        port_number: '',
        protocol: 'tcp',
        description: '',
        category: '',
        is_well_known: false,
        is_active: true,
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingMapping(null);
  };

  const handleSubmit = async () => {
    try {
      const payload = {
        ...formData,
        port_number: parseInt(formData.port_number),
      };

      const url = editingMapping 
        ? `http://localhost:5001/api/service-mappings/${editingMapping.id}`
        : 'http://localhost:5001/api/service-mappings';
      
      const method = editingMapping ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      
      if (response.ok) {
        setSnackbar({ 
          open: true, 
          message: editingMapping ? 'Service mapping updated successfully' : 'Service mapping created successfully', 
          severity: 'success' 
        });
        handleCloseDialog();
        fetchMappings();
      } else {
        throw new Error(data.error || 'Failed to save service mapping');
      }
    } catch (error) {
      console.error('Error saving service mapping:', error);
      setSnackbar({ open: true, message: error instanceof Error ? error.message : 'Failed to save service mapping', severity: 'error' });
    }
  };

  const handleDelete = async (id: number) => {
    if (!window.confirm('Are you sure you want to delete this service mapping?')) {
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/api/service-mappings/${id}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        setSnackbar({ open: true, message: 'Service mapping deleted successfully', severity: 'success' });
        fetchMappings();
      } else {
        const data = await response.json();
        throw new Error(data.error || 'Failed to delete service mapping');
      }
    } catch (error) {
      console.error('Error deleting service mapping:', error);
      setSnackbar({ open: true, message: error instanceof Error ? error.message : 'Failed to delete service mapping', severity: 'error' });
    }
  };

  const clearFilters = () => {
    setSearchTerm('');
    setCategoryFilter('');
    setProtocolFilter('');
    setWellKnownFilter('');
    setActiveFilter('');
    setPage(0);
  };

  const handleImportIANA = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/service-mappings/import/iana-txt', {
        method: 'POST'
      });
      const data = await response.json();
      if (response.ok) {
        setSnackbar({ open: true, message: `Imported ${data.created} IANA services`, severity: 'success' });
        fetchMappings();
      } else {
        throw new Error(data.error || 'Failed to import IANA services');
      }
    } catch (error) {
      setSnackbar({ open: true, message: error instanceof Error ? error.message : 'Failed to import IANA services', severity: 'error' });
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Service Port Mappings
      </Typography>
      
      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Mappings
              </Typography>
              <Typography variant="h5">
                {totalCount}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Well-Known Ports
              </Typography>
              <Typography variant="h5">
                {mappings.filter(m => m.is_well_known).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Categories
              </Typography>
              <Typography variant="h5">
                {categories.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Active Services
              </Typography>
              <Typography variant="h5">
                {mappings.filter(m => m.is_active).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters and Actions */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid size={{ xs: 12, md: 3 }}>
            <TextField
              fullWidth
              label="Search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              InputProps={{
                startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
              }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <FormControl fullWidth>
              <InputLabel>Category</InputLabel>
              <Select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                label="Category"
              >
                <MenuItem value="">All</MenuItem>
                {categories.map((category) => (
                  <MenuItem key={category} value={category}>
                    {category}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <FormControl fullWidth>
              <InputLabel>Protocol</InputLabel>
              <Select
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
                label="Protocol"
              >
                <MenuItem value="">All</MenuItem>
                {protocols.map((protocol) => (
                  <MenuItem key={protocol} value={protocol}>
                    {protocol.toUpperCase()}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <FormControl fullWidth>
              <InputLabel>Well-Known</InputLabel>
              <Select
                value={wellKnownFilter}
                onChange={(e) => setWellKnownFilter(e.target.value)}
                label="Well-Known"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="true">Yes</MenuItem>
                <MenuItem value="false">No</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, md: 3 }}>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => handleOpenDialog()}
              >
                Add Service
              </Button>
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={handleImportIANA}
              >
                Import from IANA
              </Button>
              <Tooltip title="Clear Filters">
                <IconButton onClick={clearFilters}>
                  <FilterIcon />
                </IconButton>
              </Tooltip>
              <Tooltip title="Refresh">
                <IconButton onClick={fetchMappings}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Service Name</TableCell>
              <TableCell>Port</TableCell>
              <TableCell>Protocol</TableCell>
              <TableCell>Category</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Well-Known</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={8} align="center">
                  Loading...
                </TableCell>
              </TableRow>
            ) : mappings.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} align="center">
                  No service mappings found
                </TableCell>
              </TableRow>
            ) : (
              mappings.map((mapping) => (
                <TableRow key={mapping.id}>
                  <TableCell>
                    <Typography variant="body2" fontWeight="medium">
                      {mapping.service_name}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={mapping.port_number} 
                      size="small" 
                      color="primary" 
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={mapping.protocol.toUpperCase()} 
                      size="small"
                      color={mapping.protocol === 'tcp' ? 'success' : mapping.protocol === 'udp' ? 'warning' : 'info'}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={mapping.category} 
                      size="small" 
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {mapping.description}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={mapping.is_well_known ? 'Yes' : 'No'} 
                      size="small"
                      color={mapping.is_well_known ? 'success' : 'default'}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={mapping.is_active ? 'Active' : 'Inactive'} 
                      size="small"
                      color={mapping.is_active ? 'success' : 'error'}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title="Edit">
                        <IconButton 
                          size="small" 
                          onClick={() => handleOpenDialog(mapping)}
                        >
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton 
                          size="small" 
                          color="error"
                          onClick={() => handleDelete(mapping.id)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={totalCount}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      </TableContainer>

      {/* Add/Edit Dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingMapping ? 'Edit Service Mapping' : 'Add Service Mapping'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Service Name"
                value={formData.service_name}
                onChange={(e) => setFormData({ ...formData, service_name: e.target.value })}
                required
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Port Number"
                type="number"
                value={formData.port_number}
                onChange={(e) => setFormData({ ...formData, port_number: e.target.value })}
                inputProps={{ min: 1, max: 65535 }}
                required
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth required>
                <InputLabel>Protocol</InputLabel>
                <Select
                  value={formData.protocol}
                  onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
                  label="Protocol"
                >
                  <MenuItem value="tcp">TCP</MenuItem>
                  <MenuItem value="udp">UDP</MenuItem>
                  <MenuItem value="both">Both</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Category"
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                required
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField
                fullWidth
                label="Description"
                multiline
                rows={3}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.is_well_known}
                    onChange={(e) => setFormData({ ...formData, is_well_known: e.target.checked })}
                  />
                }
                label="Well-Known Port"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.is_active}
                    onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                  />
                }
                label="Active"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button 
            onClick={handleSubmit} 
            variant="contained"
            disabled={!formData.service_name || !formData.port_number || !formData.protocol || !formData.category}
          >
            {editingMapping ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
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
    </Box>
  );
};

export default ServiceMappings;
