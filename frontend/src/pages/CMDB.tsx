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
  Avatar,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem
} from '@mui/material';
import {
  Search as SearchIcon,
  Computer as ComputerIcon,
  Storage as ServerIcon,
  Router as RouterIcon,
} from '@mui/icons-material';

interface CMDBAsset {
  id: number;
  ipAddress: string;
  hostname: string;
  owner: string;
  department: string;
  assetType: string;
  operatingSystem: string;
  location: string;
  status: string;
  pciCategory?: 'A' | 'B' | 'C';
  description?: string;
  environment?: string;
  manufacturer?: string;
  model?: string;
  applicationName?: string;
  osVersion?: string;
  macAddress?: string;
  serialNumber?: string;
  assetTag?: string;
  businessUnit?: string;
  costCenter?: string;
  sourceFile?: string;
  createdAt?: string;
  updatedAt?: string;
  lastScanDate?: string;
  warrantyExpiry?: string;
  mappedFields?: string[];
  extras?: { [key: string]: any };
}

const CMDB: React.FC = () => {
  const [assets, setAssets] = useState<CMDBAsset[]>([]);
  const [filteredAssets, setFilteredAssets] = useState<CMDBAsset[]>([]);
  const [totalAssets, setTotalAssets] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [editOpen, setEditOpen] = useState(false);
  const [selected, setSelected] = useState<CMDBAsset | null>(null);
  const [editData, setEditData] = useState<Partial<CMDBAsset>>({});
  const [editExtras, setEditExtras] = useState<{ [key: string]: any }>({});
  const [viewOpen, setViewOpen] = useState(false);
  const [viewAsset, setViewAsset] = useState<CMDBAsset | null>(null);
  const [availableFields, setAvailableFields] = useState<string[]>([]);
  const visibleEditFields = new Set<string>((selected && (selected as any).mappedFields && (selected as any).mappedFields.length > 0) ? (selected as any).mappedFields : (availableFields || []));
  const visibleViewFields = new Set<string>((viewAsset && (viewAsset as any).mappedFields && (viewAsset as any).mappedFields.length > 0) ? (viewAsset as any).mappedFields : (availableFields || []));
  const [page, setPage] = useState<number>(1);
  const [pages, setPages] = useState<number>(1);
  const [perPage, setPerPage] = useState<number>(100);

  const fetchAssets = useCallback(async (mode: 'page' | 'all' = 'page') => {
    try {
      const params = new URLSearchParams();
      if (mode === 'all') {
        params.append('per_page', 'all');
      } else {
        params.append('page', String(page));
        params.append('per_page', String(perPage));
      }
      if (searchTerm && searchTerm.trim().length > 0) params.append('search', searchTerm.trim());
      const url = `http://localhost:5001/api/cmdb?${params.toString()}`;
      const resp = await fetch(url);
      const data = await resp.json();
      if (resp.ok) {
        const mapped: CMDBAsset[] = (data.assets || []).map((a: any) => {
          const add = typeof a.additional_data === 'string' ? (() => { try { return JSON.parse(a.additional_data) } catch { return {} } })() : (a.additional_data || {});
          return {
            id: a.id,
            ipAddress: a.ip_address,
            hostname: a.hostname,
            owner: a.owner,
            department: a.department,
            assetType: a.asset_type,
            operatingSystem: a.operating_system,
            location: a.location,
            status: a.status,
            pciCategory: add?.pcidss_asset_category || undefined,
            description: a.description || add?.description || '',
            environment: a.environment || add?.environment || '',
            manufacturer: a.manufacturer || '',
            model: a.model || '',
            applicationName: add?.application_name || add?.application || add?.app_name || '',
            osVersion: a.os_version || '',
            macAddress: a.mac_address || '',
            serialNumber: a.serial_number || '',
            assetTag: a.asset_tag || '',
            businessUnit: a.business_unit || '',
            costCenter: a.cost_center || '',
            sourceFile: a.source_file || '',
            createdAt: a.created_at || '',
            updatedAt: a.updated_at || '',
            lastScanDate: a.last_scan_date || '',
            warrantyExpiry: a.warranty_expiry || '',
            mappedFields: Array.isArray(add?.__mapped_fields__) ? add.__mapped_fields__ : [],
            extras: add
          } as CMDBAsset;
        });
        setAssets(mapped);
        setFilteredAssets(mapped);
        setTotalAssets(typeof data.total === 'number' ? data.total : (mapped ? mapped.length : 0));
        setPages(typeof data.pages === 'number' ? data.pages : 1);
        try {
          const sf = mapped[0]?.sourceFile;
          const afUrl = sf && sf.trim().length > 0 ? `http://localhost:5001/api/cmdb/available-fields?source_file=${encodeURIComponent(sf)}` : 'http://localhost:5001/api/cmdb/available-fields';
          const afResp = await fetch(afUrl);
          const afData = await afResp.json();
          const fromApi: string[] = afResp.ok ? ((afData.fields as string[]) || []) : [];
          // Local union across currently loaded assets to guarantee visibility for multi-mapped uploads
          const localUnion: string[] = Array.from(new Set<string>((mapped || []).flatMap((a: CMDBAsset) => a.mappedFields || [])));
          const union: string[] = Array.from(new Set<string>([...fromApi, ...localUnion]));
          setAvailableFields(union);
        } catch (e) { /* ignore */ }
      }
    } catch (e) { console.error(e); }
  }, [page, perPage, searchTerm]);

  useEffect(() => {
    if (editOpen && selected) {
      setEditExtras(selected.extras || {});
    } else {
      setEditExtras({});
    }
  }, [editOpen, selected]);

  useEffect(() => {
    fetchAssets('page');
  }, [fetchAssets]);

  useEffect(() => {
    setPage(1);
  }, [searchTerm]);

  const getAssetIcon = (type: string | null | undefined) => {
    const t = (type || '').toLowerCase();
    switch (t) {
      case 'server':
        return <ServerIcon />;
      case 'network device':
        return <RouterIcon />;
      case 'workstation':
        return <ComputerIcon />;
      default:
        return <ComputerIcon />;
    }
  };

  const getStatusColor = (status: string | null | undefined) => {
    const s = (status || '').toLowerCase();
    switch (s) {
      case 'active':
        return 'success';
      case 'inactive':
        return 'error';
      case 'maintenance':
        return 'warning';
      default:
        return 'default';
    }
  };

  return (
    <Container maxWidth="lg">
      <Typography variant="h4" component="h1" gutterBottom>
        CMDB Assets
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Configuration Management Database - Asset Inventory
      </Typography>
      <Box sx={{ display:'flex', gap:1, mb:2 }}>
        <Button variant="contained" onClick={() => { setSelected(null); setEditData({}); setEditOpen(true); }}>Add Asset</Button>
        <Button variant="outlined" color="error" onClick={async () => {
          if (!window.confirm('Delete all CMDB assets?')) return;
          try {
            await fetch('http://localhost:5001/api/cmdb/bulk-delete', { method:'DELETE', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ delete_all: true }) });
            setAssets([]);
            setFilteredAssets([]);
          } catch (e) { console.error(e); }
        }}>Delete All</Button>
        <Button variant="outlined" onClick={() => fetchAssets('all')}>Load All</Button>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Search assets by IP, hostname, owner, or department..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'grey.500' }} />,
            }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Showing {filteredAssets.length} of {totalAssets} assets
          </Typography>
        </CardContent>
      </Card>

      <Box sx={{ display:'flex', alignItems:'center', justifyContent:'space-between', mb:2 }}>
        <Box sx={{ display:'flex', gap:1, alignItems:'center' }}>
          <Button variant="outlined" size="small" disabled={page <= 1} onClick={() => setPage(Math.max(1, page - 1))}>Previous</Button>
          <Button variant="outlined" size="small" disabled={page >= pages} onClick={() => setPage(Math.min(pages, page + 1))}>Next</Button>
          <Typography variant="caption" color="text.secondary">Page {page} / {pages}</Typography>
        </Box>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Rows</InputLabel>
          <Select value={String(perPage)} label="Rows" onChange={(e)=> setPerPage(parseInt(String(e.target.value)) || 100)}>
            <MenuItem value="50">50</MenuItem>
            <MenuItem value="100">100</MenuItem>
            <MenuItem value="200">200</MenuItem>
          </Select>
        </FormControl>
      </Box>

      <Card>
        <CardContent>
          <TableContainer component={Paper} elevation={0}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Asset</TableCell>
                  {availableFields.includes('ip_address') && (<TableCell>IP Address</TableCell>)}
                  {availableFields.includes('hostname') && (<TableCell>Hostname</TableCell>)}
                  {(availableFields.includes('application_name') || availableFields.includes('application') || availableFields.includes('app_name')) && (<TableCell>Application Name</TableCell>)}
                  {availableFields.includes('owner') && (<TableCell>Owner</TableCell>)}
                  {availableFields.includes('department') && (<TableCell>Department</TableCell>)}
                  {availableFields.includes('operating_system') && (<TableCell>OS</TableCell>)}
                  {availableFields.includes('location') && (<TableCell>Location</TableCell>)}
                  {availableFields.includes('status') && (<TableCell>Status</TableCell>)}
                  {(availableFields.includes('description') || availableFields.includes('model') || availableFields.includes('manufacturer')) && (<TableCell>Description</TableCell>)}
                  {availableFields.includes('environment') && (<TableCell>Environment</TableCell>)}
                  {availableFields.includes('pcidss_asset_category') && (<TableCell>PCI DSS Category</TableCell>)}
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredAssets.map((asset) => (
                  <TableRow key={asset.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Avatar sx={{ mr: 2, bgcolor: 'primary.light' }}>
                          {getAssetIcon(asset.assetType)}
                        </Avatar>
                        <Typography variant="body2" fontWeight="medium">
                          {asset.assetType}
                        </Typography>
                      </Box>
                    </TableCell>
                    {availableFields.includes('ip_address') && (
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {asset.ipAddress}
                        </Typography>
                      </TableCell>
                    )}
                    {availableFields.includes('hostname') && (
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {asset.hostname}
                        </Typography>
                      </TableCell>
                    )}
                    {(availableFields.includes('application_name') || availableFields.includes('application') || availableFields.includes('app_name')) && (
                      <TableCell>
                        <Typography variant="body2" color="text.primary">
                          {asset.applicationName || ''}
                        </Typography>
                      </TableCell>
                    )}
                    {availableFields.includes('owner') && (<TableCell>{asset.owner}</TableCell>)}
                    {availableFields.includes('department') && (
                      <TableCell>
                        <Chip label={asset.department} variant="outlined" size="small" />
                      </TableCell>
                    )}
                    {availableFields.includes('operating_system') && (
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {asset.operatingSystem}
                        </Typography>
                      </TableCell>
                    )}
                    {availableFields.includes('location') && (<TableCell>{asset.location}</TableCell>)}
                    {availableFields.includes('status') && (
                      <TableCell>
                        <Chip
                          label={asset.status}
                          color={getStatusColor(asset.status) as any}
                          size="small"
                        />
                      </TableCell>
                    )}
                    {(availableFields.includes('description') || availableFields.includes('model') || availableFields.includes('manufacturer')) && (
                      <TableCell>
                        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {asset.description || ''}
                        </Typography>
                      </TableCell>
                    )}
                    {availableFields.includes('environment') && (
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {asset.environment || ''}
                        </Typography>
                      </TableCell>
                    )}
                    {availableFields.includes('pcidss_asset_category') && (
                      <TableCell>
                        {asset.pciCategory ? (
                          <Chip label={`Category ${asset.pciCategory}`} size="small" />
                        ) : (
                          <Chip label="Uncategorized" variant="outlined" size="small" />
                        )}
                      </TableCell>
                    )}
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Button size="small" onClick={() => { setViewAsset(asset); setViewOpen(true); }}>View</Button>
                        <Button size="small" variant="outlined" onClick={() => { setSelected(asset); setEditData(asset); setEditOpen(true); }}>Edit</Button>
                        <Button size="small" color="error" onClick={async () => {
                          try {
                            await fetch(`http://localhost:5001/api/cmdb/${asset.id}`, { method: 'DELETE' });
                            const next = assets.filter(a => a.id !== asset.id);
                            setAssets(next);
                            setFilteredAssets(next);
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

      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>{selected ? 'Edit CMDB Asset' : 'Add CMDB Asset'}</DialogTitle>
        <DialogContent>
          <Box sx={{ display:'grid', gridTemplateColumns:'repeat(2, minmax(0, 1fr))', gap:2 }}>
            {visibleEditFields.has('hostname') && (
              <TextField label="Hostname" fullWidth value={editData.hostname || ''} onChange={(e)=>setEditData({ ...editData, hostname: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('ip_address') && (
              <TextField label="IP Address" fullWidth value={editData.ipAddress || ''} onChange={(e)=>setEditData({ ...editData, ipAddress: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('owner') && (
              <TextField label="Owner" fullWidth value={editData.owner || ''} onChange={(e)=>setEditData({ ...editData, owner: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('department') && (
              <TextField label="Department" fullWidth value={editData.department || ''} onChange={(e)=>setEditData({ ...editData, department: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('asset_type') && (
              <FormControl fullWidth>
                <InputLabel>Asset Type</InputLabel>
                <Select value={editData.assetType || ''} label="Asset Type" onChange={(e)=>setEditData({ ...editData, assetType: e.target.value as string })}>
                  <MenuItem value="Server">Server</MenuItem>
                  <MenuItem value="Workstation">Workstation</MenuItem>
                  <MenuItem value="Network Device">Network Device</MenuItem>
                </Select>
              </FormControl>
            )}
            {visibleEditFields.has('operating_system') && (
              <TextField label="Operating System" fullWidth value={editData.operatingSystem || ''} onChange={(e)=>setEditData({ ...editData, operatingSystem: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('manufacturer') && (
              <TextField label="Manufacturer" fullWidth value={editData.manufacturer || ''} onChange={(e)=>setEditData({ ...editData, manufacturer: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('model') && (
              <TextField label="Model" fullWidth value={editData.model || ''} onChange={(e)=>setEditData({ ...editData, model: e.target.value })} size="small" />
            )}
            {(visibleEditFields.has('application_name') || visibleEditFields.has('application') || visibleEditFields.has('app_name')) && (
              <TextField label="Application Name" fullWidth value={editData.applicationName || ''} onChange={(e)=>setEditData({ ...editData, applicationName: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('description') && (
              <TextField label="Description" fullWidth value={(editData as any).description || ''} onChange={(e)=>setEditData({ ...editData, description: e.target.value } as any)} size="small" />
            )}
            {visibleEditFields.has('location') && (
              <TextField label="Location" fullWidth value={editData.location || ''} onChange={(e)=>setEditData({ ...editData, location: e.target.value })} size="small" />
            )}
            {visibleEditFields.has('status') && (
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select value={editData.status || ''} label="Status" onChange={(e)=>setEditData({ ...editData, status: e.target.value as string })}>
                  <MenuItem value="active">active</MenuItem>
                  <MenuItem value="inactive">inactive</MenuItem>
                  <MenuItem value="maintenance">maintenance</MenuItem>
                </Select>
              </FormControl>
            )}
            {visibleEditFields.has('pcidss_asset_category') && (
              <FormControl fullWidth>
                <InputLabel>PCI DSS Category</InputLabel>
                <Select value={editData.pciCategory || ''} label="PCI DSS Category" onChange={(e)=>setEditData({ ...editData, pciCategory: e.target.value as any })}>
                  <MenuItem value="A">A — Cardholder data</MenuItem>
                  <MenuItem value="B">B — Supporting services to CHD environment</MenuItem>
                  <MenuItem value="C">C — No cardholder data</MenuItem>
                </Select>
              </FormControl>
            )}
            {Array.from(visibleEditFields).filter(f => ![
              'hostname','ip_address','owner','department','asset_type','operating_system','manufacturer','model',
              'application_name','description','location','status','pcidss_asset_category','os_version','mac_address',
              'serial_number','asset_tag','business_unit','cost_center','environment'
            ].includes(f)).map((f) => (
              <TextField key={f} label={f.replace(/_/g,' ').replace(/\b\w/g, (l)=>l.toUpperCase())} fullWidth size="small"
                value={String(editExtras[f] || '')}
                onChange={(e)=> setEditExtras(prev => ({...prev, [f]: e.target.value}))}
              />
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={async () => {
            try {
              const allowed = new Set<string>((selected && (selected as any).mappedFields && (selected as any).mappedFields.length > 0) ? (selected as any).mappedFields! : (availableFields || []));
              const payload: any = {};
              const payloadKeys: string[] = [];
              if (allowed.has('hostname')) payload.hostname = editData.hostname;
              if (allowed.has('hostname')) payloadKeys.push('hostname');
              if (allowed.has('ip_address')) payload.ip_address = editData.ipAddress;
              if (allowed.has('ip_address')) payloadKeys.push('ip_address');
              if (allowed.has('owner')) payload.owner = editData.owner;
              if (allowed.has('owner')) payloadKeys.push('owner');
              if (allowed.has('department')) payload.department = editData.department;
              if (allowed.has('department')) payloadKeys.push('department');
              if (allowed.has('asset_type')) payload.asset_type = editData.assetType;
              if (allowed.has('asset_type')) payloadKeys.push('asset_type');
              if (allowed.has('operating_system')) payload.operating_system = editData.operatingSystem;
              if (allowed.has('operating_system')) payloadKeys.push('operating_system');
              if (allowed.has('manufacturer')) payload.manufacturer = editData.manufacturer;
              if (allowed.has('manufacturer')) payloadKeys.push('manufacturer');
              if (allowed.has('model')) payload.model = editData.model;
              if (allowed.has('model')) payloadKeys.push('model');
              if (allowed.has('location')) payload.location = editData.location;
              if (allowed.has('location')) payloadKeys.push('location');
              if (allowed.has('status')) payload.status = editData.status;
              if (allowed.has('status')) payloadKeys.push('status');
              const add: any = {};
              if (allowed.has('application_name') || allowed.has('application') || allowed.has('app_name')) add.application_name = editData.applicationName;
              if (allowed.has('application_name') || allowed.has('application') || allowed.has('app_name')) payloadKeys.push('application_name');
              if (allowed.has('description')) add.description = (editData as any).description;
              if (allowed.has('description')) payloadKeys.push('description');
              Array.from(allowed).forEach((f) => {
                if (!['hostname','ip_address','owner','department','asset_type','operating_system','manufacturer','model','location','status','pcidss_asset_category'].includes(f)) {
                  const v = (editExtras || {})[f];
                  if (typeof v !== 'undefined') {
                    add[f] = v;
                    payloadKeys.push(f);
                  }
                }
              });
              if (Object.keys(add).length > 0) { add.__mapped_fields__ = Array.from(new Set<string>(payloadKeys)); payload.additional_data = add; }
              if (selected) {
              const resp = await fetch(`http://localhost:5001/api/cmdb/${selected.id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              if (resp.ok) {
                const next = assets.map(a => a.id === selected.id ? { ...a, ...editData } as CMDBAsset : a);
                setAssets(next);
                setFilteredAssets(next);
                setEditOpen(false);
              }
            } else {
                const postBody: any = { ...payload, source_file: 'manual' };
                if (allowed.has('pcidss_asset_category')) postBody.pcidss_asset_category = editData.pciCategory;
                const resp = await fetch('http://localhost:5001/api/cmdb', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(postBody) });
                const d = await resp.json();
                if (resp.ok) {
                  const add = typeof d.asset.additional_data === 'string' ? (() => { try { return JSON.parse(d.asset.additional_data) } catch { return {} } })() : (d.asset.additional_data || {});
                  const created: CMDBAsset = {
                    id: d.asset.id,
                    ipAddress: d.asset.ip_address,
                    hostname: d.asset.hostname,
                    owner: d.asset.owner,
                    department: d.asset.department,
                    assetType: d.asset.asset_type,
                    operatingSystem: d.asset.operating_system,
                    location: d.asset.location,
                    status: d.asset.status,
                    pciCategory: add?.pcidss_asset_category || (editData.pciCategory as any),
                    description: add?.description || '',
                    environment: d.asset.environment || '',
                    manufacturer: d.asset.manufacturer || (editData.manufacturer as any) || '',
                    model: d.asset.model || (editData.model as any) || '',
                    applicationName: add?.application_name || (editData.applicationName as any) || '',
                    osVersion: d.asset.os_version || '',
                    macAddress: d.asset.mac_address || '',
                    serialNumber: d.asset.serial_number || '',
                    assetTag: d.asset.asset_tag || '',
                    businessUnit: d.asset.business_unit || '',
                    costCenter: d.asset.cost_center || '',
                    sourceFile: d.asset.source_file || '',
                    createdAt: d.asset.created_at || '',
                    updatedAt: d.asset.updated_at || '',
                    lastScanDate: d.asset.last_scan_date || '',
                    warrantyExpiry: d.asset.warranty_expiry || '',
                    mappedFields: Array.isArray(add?.__mapped_fields__) ? add.__mapped_fields__ : []
                  };
                  const next = [created, ...assets];
                  setAssets(next);
                  setFilteredAssets(next);
                  setEditOpen(false);
                }
              }
            } catch (e) { console.error(e); }
          }}>Save</Button>
        </DialogActions>
      </Dialog>
      <Dialog open={viewOpen} onClose={() => setViewOpen(false)} fullWidth maxWidth="md" scroll="paper">
        <DialogTitle>Asset Details</DialogTitle>
        <DialogContent sx={{ maxHeight: '60vh', overflowY: 'auto' }}>
          {viewAsset && (
            <Box sx={{ display:'grid', gridTemplateColumns:'repeat(2, minmax(0, 1fr))', gap:2, alignItems:'start' }}>
              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', fontWeight: 600 }}>Identity</Typography>
              {visibleViewFields.has('hostname') && (<TextField label="Hostname" value={viewAsset.hostname || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('ip_address') && (<TextField label="IP Address" value={viewAsset.ipAddress || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt:1, fontWeight: 600 }}>Ownership</Typography>
              {visibleViewFields.has('owner') && (<TextField label="Owner" value={viewAsset.owner || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('department') && (<TextField label="Department" value={viewAsset.department || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('business_unit') && (<TextField label="Business Unit" value={viewAsset.businessUnit || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('cost_center') && (<TextField label="Cost Center" value={viewAsset.costCenter || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt:1, fontWeight: 600 }}>System</Typography>
              {visibleViewFields.has('asset_type') && (<TextField label="Asset Type" value={viewAsset.assetType || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('operating_system') && (<TextField label="Operating System" value={viewAsset.operatingSystem || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('os_version') && (<TextField label="OS Version" value={viewAsset.osVersion || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('manufacturer') && (<TextField label="Manufacturer" value={viewAsset.manufacturer || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('model') && (<TextField label="Model" value={viewAsset.model || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {(visibleViewFields.has('application_name') || visibleViewFields.has('application') || visibleViewFields.has('app_name')) && (<TextField label="Application Name" value={viewAsset.applicationName || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('mac_address') && (<TextField label="MAC Address" value={viewAsset.macAddress || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('serial_number') && (<TextField label="Serial Number" value={viewAsset.serialNumber || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('asset_tag') && (<TextField label="Asset Tag" value={viewAsset.assetTag || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt:1, fontWeight: 600 }}>Location & Status</Typography>
              {visibleViewFields.has('location') && (<TextField label="Location" value={viewAsset.location || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('environment') && (<TextField label="Environment" value={viewAsset.environment || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('status') && (<TextField label="Status" value={viewAsset.status || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt:1, fontWeight: 600 }}>Details</Typography>
              {visibleViewFields.has('description') && (<TextField label="Description" value={viewAsset.description || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {visibleViewFields.has('pcidss_asset_category') && (<TextField label="PCI DSS Category" value={viewAsset.pciCategory || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />)}
              {Array.from(visibleViewFields).filter(f => ![
                'hostname','ip_address','owner','department','asset_type','operating_system','manufacturer','model',
                'application_name','description','location','status','pcidss_asset_category','os_version','mac_address',
                'serial_number','asset_tag','business_unit','cost_center','environment'
              ].includes(f)).map((f) => (
                <TextField key={f} label={f.replace(/_/g,' ').replace(/\b\w/g, (l)=>l.toUpperCase())} value={String(((viewAsset as any)?.extras||{})[f] || '')} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />
              ))}
              <TextField label="Source File" value={viewAsset.sourceFile || ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />

              <Typography variant="subtitle1" sx={{ gridColumn: '1 / -1', mt:1, fontWeight: 600 }}>Timeline</Typography>
              <TextField label="Created At" value={viewAsset.createdAt ? new Date(viewAsset.createdAt).toLocaleString() : ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />
              <TextField label="Updated At" value={viewAsset.updatedAt ? new Date(viewAsset.updatedAt).toLocaleString() : ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />
              <TextField label="Last Scan" value={viewAsset.lastScanDate ? new Date(viewAsset.lastScanDate).toLocaleString() : ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />
              <TextField label="Warranty Expiry" value={viewAsset.warrantyExpiry ? new Date(viewAsset.warrantyExpiry).toLocaleDateString() : ''} fullWidth InputProps={{ readOnly: true }} variant="outlined" size="small" />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default CMDB;
