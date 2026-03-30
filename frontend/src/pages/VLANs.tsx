import React, { useState, useEffect } from 'react';
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
  Avatar,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField as MuiTextField,
  Checkbox,
  Snackbar,
  Alert
} from '@mui/material';
import {
  Search as SearchIcon,
  NetworkCheck as NetworkIcon,
  Upload as UploadIcon,
  Delete as DeleteIcon
} from '@mui/icons-material';
import EnhancedColumnMappingDialog from '../components/EnhancedColumnMappingDialog';

interface VLANNetwork {
  id: number;
  vlanId: number;
  name: string;
  subnet: string;
  description: string;
  gateway: string;
  location?: string;
}

const VLANs: React.FC = () => {
  const [vlans, setVlans] = useState<VLANNetwork[]>([]);
  const [filteredVlans, setFilteredVlans] = useState<VLANNetwork[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [selected, setSelected] = useState<VLANNetwork | null>(null);
  const [editData, setEditData] = useState<Partial<VLANNetwork>>({});
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });

  const fetchVlans = async () => {
    try {
      const resp = await fetch('http://localhost:5001/api/vlans?per_page=500');
      const data = await resp.json();
      if (resp.ok) {
        const mapped = (data.vlans || []).map((v: any) => ({
          id: v.id,
          vlanId: v.vlan_id,
          name: v.name,
          subnet: v.subnet,
          description: v.description,
          gateway: v.gateway,
          location: v.location
        }));
        setVlans(mapped);
        setFilteredVlans(mapped);
      }
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    fetchVlans();
  }, []);

  useEffect(() => {
    if (searchTerm) {
      const filtered = vlans.filter(vlan =>
        (vlan.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (vlan.subnet || '').includes(searchTerm) ||
        (vlan.description || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (vlan.location || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        vlan.vlanId.toString().includes(searchTerm)
      );
      setFilteredVlans(filtered);
    } else {
      setFilteredVlans(vlans);
    }
  }, [searchTerm, vlans]);

  const toggleSelectAll = () => {
    if (filteredVlans.length === 0) return;
    if (selectedIds.length === filteredVlans.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredVlans.map((v) => v.id));
    }
  };

  const toggleSelectRow = (id: number) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const bulkDeleteSelected = async () => {
    if (!selectedIds.length) return;
    if (!window.confirm(`Delete ${selectedIds.length} selected VLANs?`)) return;
    try {
      const resp = await fetch('http://localhost:5001/api/vlans/bulk-delete', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vlan_ids: selectedIds })
      });
      if (resp.ok) {
        setSnackbar({ open: true, message: 'Selected VLANs deleted', severity: 'success' });
        setSelectedIds([]);
        fetchVlans();
      } else {
        setSnackbar({ open: true, message: 'Failed to delete VLANs', severity: 'error' });
      }
    } catch (e) { console.error(e); }
  };

  const handleImportSave = async (mapping: { [key: string]: string | string[] }) => {
    if (!importFile) return;

    const formData = new FormData();
    formData.append('file', importFile);
    formData.append('mapping', JSON.stringify(mapping));

    try {
      const response = await fetch('http://localhost:5001/api/vlans/import', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const result = await response.json();
        setSnackbar({
          open: true,
          message: `Imported ${result.count} VLANs successfully`,
          severity: 'success'
        });
        setImportOpen(false);
        setImportFile(null);
        fetchVlans();
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
    }
  };

  const getVlanColor = (vlanId: number) => {
    const colors = ['primary', 'secondary', 'success', 'warning', 'error', 'info'];
    return colors[vlanId % colors.length];
  };

  return (
    <Container maxWidth="lg">
      <Typography variant="h4" component="h1" gutterBottom>
        VLAN Networks
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Virtual Local Area Network configuration and management
      </Typography>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Search VLANs by ID, name, subnet, or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'grey.500' }} />,
            }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Showing {filteredVlans.length} of {vlans.length} VLANs
          </Typography>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <TableContainer component={Paper} elevation={0}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>VLAN</TableCell>
                  <TableCell>VLAN ID</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Subnet</TableCell>
                  <TableCell>Gateway</TableCell>
                  <TableCell>Location</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredVlans.map((vlan) => (
                  <TableRow key={vlan.id} hover selected={selectedIds.includes(vlan.id)}>
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={selectedIds.includes(vlan.id)}
                        onChange={() => toggleSelectRow(vlan.id)}
                      />
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Avatar sx={{ mr: 2, bgcolor: `${getVlanColor(vlan.vlanId)}.light` }}>
                          <NetworkIcon />
                        </Avatar>
                        <Typography variant="body2" fontWeight="medium">
                          VLAN {vlan.vlanId}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={vlan.vlanId}
                        color={getVlanColor(vlan.vlanId) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {vlan.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {vlan.subnet}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {vlan.gateway}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {vlan.location || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {vlan.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display:'flex', gap:1 }}>
                        <Button size="small" variant="outlined" onClick={() => { setSelected(vlan); setEditData(vlan); setEditOpen(true); }}>Edit</Button>
                        <Button size="small" color="error" onClick={async () => {
                          try {
                            await fetch(`http://localhost:5001/api/vlans/${vlan.id}`, { method: 'DELETE' });
                            const next = vlans.filter(v => v.id !== vlan.id);
                            setVlans(next);
                            setFilteredVlans(next);
                          } catch (e) { console.error(e); }
                        }}>Delete</Button>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
      <Box sx={{ display:'flex', gap:1, mt:2 }}>
        <Button variant="contained" onClick={() => { setSelected(null); setEditData({}); setEditOpen(true); }}>Add VLAN</Button>
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
          Import VLANs
        </Button>
        <Button variant="outlined" onClick={() => window.open('http://localhost:5001/api/import-templates/vlan-object-group', '_blank')}>Download Template</Button>
        <Button 
          variant="outlined" 
          color="error" 
          startIcon={<DeleteIcon />}
          onClick={bulkDeleteSelected}
          disabled={!selectedIds.length}
        >
          Delete Selected
        </Button>
        <Button variant="outlined" color="error" onClick={async () => {
          if (!window.confirm('Delete all VLANs?')) return;
          try {
            await fetch('http://localhost:5001/api/vlans/bulk-delete', { method:'DELETE', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ delete_all: true }) });
            setVlans([]);
            setFilteredVlans([]);
          } catch (e) { console.error(e); }
        }}>Delete All</Button>
      </Box>

      <EnhancedColumnMappingDialog
        open={importOpen}
        file={importFile}
        fileType="vlan"
        onClose={() => { setImportOpen(false); setImportFile(null); }}
        onSave={handleImportSave}
      />

      <Snackbar open={snackbar.open} autoHideDuration={6000} onClose={() => setSnackbar({ ...snackbar, open: false })}>
        <Alert severity={snackbar.severity}>{snackbar.message}</Alert>
      </Snackbar>

      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>{selected ? 'Edit VLAN' : 'Add VLAN'}</DialogTitle>
        <DialogContent>
          <MuiTextField label="VLAN ID" fullWidth sx={{ mt:2 }} value={editData.vlanId || ''} onChange={(e)=>setEditData({ ...editData, vlanId: Number(e.target.value) })} />
          <MuiTextField label="Name" fullWidth sx={{ mt:2 }} value={editData.name || ''} onChange={(e)=>setEditData({ ...editData, name: e.target.value })} />
          <MuiTextField label="Subnet" fullWidth sx={{ mt:2 }} value={editData.subnet || ''} onChange={(e)=>setEditData({ ...editData, subnet: e.target.value })} />
          <MuiTextField label="Gateway" fullWidth sx={{ mt:2 }} value={editData.gateway || ''} onChange={(e)=>setEditData({ ...editData, gateway: e.target.value })} />
          <MuiTextField label="Location" fullWidth sx={{ mt:2 }} value={editData.location || ''} onChange={(e)=>setEditData({ ...editData, location: e.target.value })} />
          <MuiTextField label="Description" fullWidth sx={{ mt:2 }} value={editData.description || ''} onChange={(e)=>setEditData({ ...editData, description: e.target.value })} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={async () => {
            try {
              const payload = {
                vlan_id: editData.vlanId,
                name: editData.name,
                subnet: editData.subnet,
                gateway: editData.gateway,
                description: editData.description,
                location: editData.location
              };
              if (selected) {
                const resp = await fetch(`http://localhost:5001/api/vlans/${selected.id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
                if (resp.ok) {
                  const next = vlans.map(v => v.id === selected.id ? { ...v, ...editData } as VLANNetwork : v);
                  setVlans(next);
                  setFilteredVlans(next);
                  setEditOpen(false);
                }
              } else {
                const resp = await fetch('http://localhost:5001/api/vlans', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ...payload, source_file:'manual', status:'active', vlan_type:'access' }) });
                const d = await resp.json();
                if (resp.ok) {
                  const created: VLANNetwork = { id: d.vlan.id, vlanId: d.vlan.vlan_id, name: d.vlan.name, subnet: d.vlan.subnet, description: d.vlan.description, gateway: d.vlan.gateway, location: d.vlan.location };
                  const next = [created, ...vlans];
                  setVlans(next);
                  setFilteredVlans(next);
                  setEditOpen(false);
                }
              }
            } catch (e) { console.error(e); }
          }}>Save</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default VLANs;
