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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Alert,
  Snackbar,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Divider,
  CircularProgress,
  Checkbox,
  TablePagination,
} from '@mui/material';
import {
  Search as SearchIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Group as GroupIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  DeleteSweep as DeleteSweepIcon,
  Upload as UploadIcon,
} from '@mui/icons-material';
import EnhancedColumnMappingDialog from '../components/EnhancedColumnMappingDialog';


interface ObjectGroup {
  id: number;
  name: string;
  group_type: string;
  status: string;
  description: string;
  vendor: string;
  source_file: string;
  created_at: string;
  updated_at: string;
  members?: ObjectGroupMember[];
  member_count?: number;
  member_values_preview?: string[];
}

interface ObjectGroupMember {
  id: number;
  object_group_id: number;
  member_type: string;
  member_value: string;
  description: string;
  created_at: string;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const ObjectGroups: React.FC = () => {
  const [groups, setGroups] = useState<ObjectGroup[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [filteredGroups, setFilteredGroups] = useState<ObjectGroup[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [selectedGroup, setSelectedGroup] = useState<ObjectGroup | null>(null);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [membersDialogOpen, setMembersDialogOpen] = useState(false);
  const [newMember, setNewMember] = useState({ member_type: 'ip', member_value: '', description: '' });
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [normalizing, setNormalizing] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' | 'warning' | 'info' });
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [page, setPage] = useState(0);
  const [perPage, setPerPage] = useState(10);
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);

  const fetchGroups = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page + 1));
      params.set('per_page', String(perPage));
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (typeFilter !== 'all') params.set('type', typeFilter);
      const response = await fetch(`http://localhost:5001/api/object-groups?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        setGroups(data.object_groups || []);
        setTotalCount(typeof data.total === 'number' ? data.total : (data.object_groups ? data.object_groups.length : 0));
      } else {
        throw new Error('Failed to fetch object groups');
      }
    } catch (error) {
      console.error('Error fetching object groups:', error);
      setSnackbar({ open: true, message: 'Failed to fetch object groups', severity: 'error' });
    } finally {
      setLoading(false);
    }
  }, [page, perPage, statusFilter, typeFilter]);

  const fetchGroupWithMembers = async (groupId: number) => {
    try {
      const response = await fetch(`http://localhost:5001/api/object-groups/${groupId}`);
      if (response.ok) {
        const group = await response.json();
        setSelectedGroup(group);
        return group;
      } else {
        throw new Error('Failed to fetch group details');
      }
    } catch (error) {
      console.error('Error fetching group details:', error);
      setSnackbar({ open: true, message: 'Failed to fetch group details', severity: 'error' });
      return null;
    }
  };

  const scanObjectGroups = async () => {
    setScanning(true);
    try {
      const response = await fetch('http://localhost:5001/api/scan-object-groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      let data: any = null;
      try {
        data = await response.json();
      } catch {
        data = null;
      }

      if (response.ok) {
        const created = data?.results?.new_groups_created ?? 0;
        setSnackbar({
          open: true,
          message: `Scan completed: ${created} new groups found`,
          severity: 'success'
        });
        fetchGroups();
      } else {
        const errorMessage = data?.error || data?.message || 'Failed to scan object groups';
        throw new Error(errorMessage);
      }
    } catch (error) {
      console.error('Error scanning object groups:', error);
      const message = error instanceof Error ? error.message : 'Failed to scan object groups';
      setSnackbar({ open: true, message, severity: 'error' });
    } finally {
      setScanning(false);
    }
  };

  const normalizeRules = async () => {
    setNormalizing(true);
    try {
      const response = await fetch('http://localhost:5001/api/normalize-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force_all: true })
      });
      
      if (response.ok) {
        const data = await response.json();
        setSnackbar({ 
          open: true, 
          message: `Normalization completed: ${data.results.stats.normalized_rules_created} rules processed`, 
          severity: 'success' 
        });
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to normalize rules');
      }
    } catch (error) {
      console.error('Error normalizing rules:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to normalize rules';
      setSnackbar({ open: true, message: errorMessage, severity: 'error' });
    } finally {
      setNormalizing(false);
    }
  };

  const updateGroupMembers = async (groupId: number, members: any[]) => {
    try {
      const response = await fetch(`http://localhost:5001/api/object-groups/${groupId}/members`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ members })
      });
      
      if (response.ok) {
        setSnackbar({ open: true, message: 'Members updated successfully', severity: 'success' });
        fetchGroups();
        if (selectedGroup) {
          fetchGroupWithMembers(groupId);
        }
      } else {
        throw new Error('Failed to update members');
      }
    } catch (error) {
      console.error('Error updating members:', error);
      setSnackbar({ open: true, message: 'Failed to update members', severity: 'error' });
    }
  };

  const addMember = async () => {
    if (!selectedGroup || !newMember.member_value.trim()) return;

    try {
      const response = await fetch(`http://localhost:5001/api/object-groups/${selectedGroup.id}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newMember)
      });
      
      if (response.ok) {
        setSnackbar({ open: true, message: 'Member added successfully', severity: 'success' });
        setNewMember({ member_type: 'ip', member_value: '', description: '' });
        // Refresh both the selected group's members and the main list to reflect status
        fetchGroups();
        fetchGroupWithMembers(selectedGroup.id);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to add member');
      }
    } catch (error: any) {
      console.error('Error adding member:', error);
      setSnackbar({ open: true, message: error.message, severity: 'error' });
    }
  };

  const deleteMember = async (memberId: number) => {
    if (!selectedGroup) return;

    try {
      const response = await fetch(`http://localhost:5001/api/object-groups/${selectedGroup.id}/members/${memberId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setSnackbar({ open: true, message: 'Member deleted successfully', severity: 'success' });
        // Refresh both the selected group's members and the main list to reflect status
        fetchGroups();
        fetchGroupWithMembers(selectedGroup.id);
      } else {
        throw new Error('Failed to delete member');
      }
    } catch (error) {
      console.error('Error deleting member:', error);
      setSnackbar({ open: true, message: 'Failed to delete member', severity: 'error' });
    }
  };

  useEffect(() => {
    fetchGroups();
  }, [fetchGroups]);

  useEffect(() => {
    // Reset to first page when server-side filters change
    setPage(0);
  }, [statusFilter, typeFilter]);

  const handleChangePage = (_: any, newPage: number) => {
    setSelectedIds([]);
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    const newSize = parseInt(event.target.value, 10);
    setSelectedIds([]);
    setPerPage(newSize);
    setPage(0);
  };

  useEffect(() => {
    let filtered = groups;

    if (searchTerm) {
      const q = (searchTerm || '').toLowerCase();
      filtered = filtered.filter(group => {
        const name = (group.name || '').toLowerCase();
        const desc = (group.description || '').toLowerCase();
        return name.includes(q) || desc.includes(q);
      });
    }

    if (statusFilter !== 'all') {
      filtered = filtered.filter(group => group.status === statusFilter);
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(group => group.group_type === typeFilter);
    }

    setFilteredGroups(filtered);
  }, [groups, searchTerm, statusFilter, typeFilter]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'resolved':
        return <CheckCircleIcon color="success" />;
      case 'unresolved':
        return <WarningIcon color="warning" />;
      default:
        return <ErrorIcon color="error" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'resolved':
        return 'success';
      case 'unresolved':
        return 'warning';
      default:
        return 'error';
    }
  };

  const handleEditGroup = async (group: ObjectGroup) => {
    const groupWithMembers = await fetchGroupWithMembers(group.id);
    if (groupWithMembers) {
      setSelectedGroup(groupWithMembers);
      setMembersDialogOpen(true);
    }
  };

  const toggleSelectAll = () => {
    if (filteredGroups.length === 0) return;
    if (selectedIds.length === filteredGroups.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredGroups.map((g) => g.id));
    }
  };

  const toggleSelectRow = (id: number) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const deleteGroup = async (groupId: number) => {
    if (!window.confirm('Delete this object group?')) return;
    try {
      const response = await fetch(`http://localhost:5001/api/object-groups/${groupId}`, { method: 'DELETE' });
      if (response.ok) {
        setSnackbar({ open: true, message: 'Object group deleted successfully', severity: 'success' });
        fetchGroups();
      } else {
        const err = await response.json();
        throw new Error(err.error || 'Failed to delete object group');
      }
    } catch (error: any) {
      console.error('Error deleting object group:', error);
      setSnackbar({ open: true, message: error.message || 'Failed to delete object group', severity: 'error' });
    }
  };

  const bulkDeleteSelected = async () => {
    if (selectedIds.length === 0) return;
    if (!window.confirm(`Delete ${selectedIds.length} selected object group(s)?`)) return;
    try {
      const response = await fetch('http://localhost:5001/api/object-groups/bulk-delete', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_ids: selectedIds }),
      });
      if (response.ok) {
        const data = await response.json();
        setSnackbar({ open: true, message: `Deleted ${data.deleted_count} object group(s)`, severity: 'success' });
        setSelectedIds([]);
        fetchGroups();
      } else {
        const err = await response.json();
        throw new Error(err.error || 'Failed to bulk delete');
      }
    } catch (error: any) {
      console.error('Error bulk deleting object groups:', error);
      setSnackbar({ open: true, message: error.message || 'Failed to bulk delete', severity: 'error' });
    }
  };

  const deleteAllGroups = async () => {
    const mode = statusFilter !== 'all' ? `Delete all with status "${statusFilter}"` : 'Delete ALL object groups';
    if (!window.confirm(`${mode}? This cannot be undone.`)) return;
    try {
      const payload = statusFilter !== 'all' ? { status: statusFilter } : { delete_all: true };
      const response = await fetch('http://localhost:5001/api/object-groups/bulk-delete', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (response.ok) {
        const data = await response.json();
        setSnackbar({ open: true, message: `Deleted ${data.deleted_count} object group(s)`, severity: 'success' });
        setSelectedIds([]);
        fetchGroups();
      } else {
        const err = await response.json();
        throw new Error(err.error || 'Failed to delete all');
      }
    } catch (error: any) {
      console.error('Error deleting all object groups:', error);
      setSnackbar({ open: true, message: error.message || 'Failed to delete all', severity: 'error' });
    }
  };

  const handleImportSave = async (mapping: { [key: string]: string | string[] }) => {
    if (!importFile) return;

    setImporting(true);
    const formData = new FormData();
    formData.append('file', importFile);
    formData.append('mapping', JSON.stringify(mapping));

    try {
      const response = await fetch('http://localhost:5001/api/object-groups/import', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const result = await response.json();
        setSnackbar({
          open: true,
          message: `Imported ${result.count} Object Groups successfully`,
          severity: 'success'
        });
        setImportOpen(false);
        setImportFile(null);
        fetchGroups();
      } else {
        const error = await response.json();
        setSnackbar({
          open: true,
          message: `Import failed: ${error.error || 'Unknown error'}`,
          severity: 'error'
        });
      }
    } catch (e) {
      console.error(e);
      setSnackbar({
        open: true,
        message: 'Import failed: Network error',
        severity: 'error'
      });
    } finally {
      setImporting(false);
    }
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <GroupIcon fontSize="large" />
          Object Group Management
          <Chip label={`${filteredGroups.length} shown`} color="secondary" variant="outlined" sx={{ ml: 2 }} />
          <Chip label={`${totalCount} total`} color="primary" variant="outlined" sx={{ ml: 1 }} />
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            color="secondary"
            startIcon={<UploadIcon />}
            onClick={() => {
              const input = document.createElement('input');
              input.type = 'file';
              input.accept = '.csv,.xlsx';
              input.onchange = (e: any) => {
                if (e.target.files?.[0]) {
                  setImportFile(e.target.files[0]);
                  setImportOpen(true);
                }
              };
              input.click();
            }}
          >
            Import
          </Button>
          <Button
            variant="outlined"
            onClick={() => window.open('http://localhost:5001/api/import-templates/vlan-object-group', '_blank')}
          >
            Download Template
          </Button>
          <Button
            variant="outlined"
            startIcon={scanning ? <CircularProgress size={20} /> : <RefreshIcon />}
            onClick={scanObjectGroups}
            disabled={scanning}
          >
            {scanning ? 'Scanning...' : 'Scan for Groups'}
          </Button>
          <Button
            variant="contained"
            startIcon={normalizing ? <CircularProgress size={20} /> : <PlayArrowIcon />}
            onClick={normalizeRules}
            disabled={normalizing}
          >
            {normalizing ? 'Normalizing...' : 'Normalize Rules'}
          </Button>
        </Box>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <TextField
              label="Search Groups"
              variant="outlined"
              size="small"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              InputProps={{
                startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
              }}
              sx={{ minWidth: 250 }}
            />
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                label="Status"
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <MenuItem value="all">All Status</MenuItem>
                <MenuItem value="unresolved">Unresolved</MenuItem>
                <MenuItem value="resolved">Resolved</MenuItem>
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Type</InputLabel>
              <Select
                value={typeFilter}
                label="Type"
                onChange={(e) => setTypeFilter(e.target.value)}
              >
                <MenuItem value="all">All Types</MenuItem>
                <MenuItem value="network">Network</MenuItem>
                <MenuItem value="service">Service</MenuItem>
                <MenuItem value="application">Application</MenuItem>
              </Select>
            </FormControl>
            <Box sx={{ display: 'flex', gap: 1, ml: 'auto' }}>
              <Button
                variant="outlined"
                color="error"
                startIcon={<DeleteIcon />}
                onClick={bulkDeleteSelected}
                disabled={selectedIds.length === 0}
              >
                Delete Selected
              </Button>
              <Button
                variant="outlined"
                color="error"
                startIcon={<DeleteSweepIcon />}
                onClick={deleteAllGroups}
                disabled={filteredGroups.length === 0}
              >
                Delete All
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            <>
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox">
                      <Checkbox
                        indeterminate={selectedIds.length > 0 && selectedIds.length < filteredGroups.length}
                        checked={filteredGroups.length > 0 && selectedIds.length === filteredGroups.length}
                        onChange={toggleSelectAll}
                      />
                    </TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Members</TableCell>
                    <TableCell>Source File</TableCell>
                    <TableCell>Vendor</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredGroups.map((group) => (
                    <TableRow key={group.id} hover>
                      <TableCell padding="checkbox">
                        <Checkbox
                          checked={selectedIds.includes(group.id)}
                          onChange={() => toggleSelectRow(group.id)}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {getStatusIcon(group.status)}
                          <Chip
                            label={group.status}
                            color={getStatusColor(group.status) as any}
                            size="small"
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {group.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={group.group_type} variant="outlined" size="small" />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {group.description || 'No description'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {group.member_count ? `${group.member_count} member${group.member_count > 1 ? 's' : ''}` : 'No members'}
                        </Typography>
                        {group.member_values_preview && group.member_values_preview.length > 0 && (
                          <Typography variant="body2" color="text.secondary" noWrap>
                            {group.member_values_preview.join(', ')}
                            {group.member_count && group.member_count > group.member_values_preview.length ? ' …' : ''}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {group.source_file}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {group.vendor}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title="Manage Members">
                          <IconButton
                            size="small"
                            onClick={() => handleEditGroup(group)}
                            color="primary"
                          >
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete Group">
                          <IconButton
                            size="small"
                            onClick={() => deleteGroup(group.id)}
                            color="error"
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredGroups.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={9} align="center">
                        <Typography variant="body2" color="text.secondary" sx={{ py: 4 }}>
                          No object groups found
                        </Typography>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              component="div"
              count={totalCount}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={perPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
            </>
          )}
        </CardContent>
      </Card>

      {/* Import Dialog */}
      <EnhancedColumnMappingDialog
        open={importOpen}
        file={importFile}
        fileType="objects"
        onClose={() => {
          setImportOpen(false);
          setImportFile(null);
        }}
        onSave={handleImportSave}
      />

      <Dialog
        open={membersDialogOpen}
        onClose={() => setMembersDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Manage Members: {selectedGroup?.name}
        </DialogTitle>
        <DialogContent>
          {selectedGroup && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="h6" gutterBottom>
                Add New Member
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 3 }}>
                <Box sx={{ minWidth: 200 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Type</InputLabel>
                    <Select
                      value={newMember.member_type}
                      label="Type"
                      onChange={(e) => setNewMember({ ...newMember, member_type: e.target.value })}
                    >
                      <MenuItem value="ip">IP Address</MenuItem>
                      <MenuItem value="subnet">Subnet</MenuItem>
                      <MenuItem value="range">IP Range</MenuItem>
                      <MenuItem value="service">Service</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
                <Box sx={{ minWidth: 250 }}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Value"
                    value={newMember.member_value}
                    onChange={(e) => setNewMember({ ...newMember, member_value: e.target.value })}
                    placeholder="e.g., 192.168.1.100"
                  />
                </Box>
                <Box sx={{ minWidth: 200 }}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Description"
                    value={newMember.description}
                    onChange={(e) => setNewMember({ ...newMember, description: e.target.value })}
                  />
                </Box>
                <Box>
                  <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={addMember}
                    disabled={!newMember.member_value.trim()}
                  >
                    Add
                  </Button>
                </Box>
              </Box>

              <Divider sx={{ my: 2 }} />

              <Typography variant="h6" gutterBottom>
                Current Members ({selectedGroup.members?.length || 0})
              </Typography>
              {selectedGroup.members && selectedGroup.members.length > 0 ? (
                <List>
                  {selectedGroup.members.map((member) => (
                    <ListItem key={member.id} divider>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip label={member.member_type} size="small" variant="outlined" />
                            <Typography variant="body1" fontWeight="medium" component="span">
                              {member.member_value}
                            </Typography>
                          </Box>
                        }
                        secondary={member.description || 'No description'}
                      />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          onClick={() => deleteMember(member.id)}
                          color="error"
                          size="small"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="info">
                  No members defined for this group. Add members to resolve this object group.
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMembersDialogOpen(false)}>
            Close
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
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ObjectGroups;
