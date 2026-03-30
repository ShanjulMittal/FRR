import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Alert,
  Chip,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Grid,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  InsertDriveFile as FileIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  Settings as SettingsIcon,
  Visibility as PreviewIcon,
  AutoFixHigh as SmartIcon,
} from '@mui/icons-material';
import { apiService } from '../services/api';
import EnhancedColumnMappingDialog from '../components/EnhancedColumnMappingDialog';

interface UploadedFile {
  name: string;
  size: number;
  type: 'firewall' | 'cmdb' | 'vlan' | 'objects';
  status: 'pending' | 'uploading' | 'success' | 'error' | 'mapping';
  progress: number;
  error?: string;
  file?: File;
  previewData?: any[];
  columnMapping?: { [key: string]: string };
}

const Uploads: React.FC = () => {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [selectedFileType, setSelectedFileType] = useState<'firewall' | 'cmdb' | 'vlan' | 'objects'>('firewall');
  const [mappingDialog, setMappingDialog] = useState<{
    open: boolean;
    file: File | null;
    fileType: 'firewall' | 'cmdb' | 'vlan' | 'objects';
  }>({ open: false, file: null, fileType: 'firewall' });

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    handleFiles(droppedFiles);
  }, [selectedFileType]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files);
      handleFiles(selectedFiles);
    }
  }, [selectedFileType]);

  const handleFiles = async (fileList: File[]) => {
    const newFiles: UploadedFile[] = fileList.map(file => ({
      name: file.name,
      size: file.size,
      type: selectedFileType,
      status: 'pending',
      progress: 0,
      file: file,
    }));

    setFiles(prev => [...prev, ...newFiles]);

    // Process each file
    for (let i = 0; i < newFiles.length; i++) {
      const fileIndex = files.length + i;
      await processFile(newFiles[i], fileIndex);
    }
  };

  const processFile = async (uploadFile: UploadedFile, index: number) => {
    if (!uploadFile.file) return;

    // Check if file needs column mapping (CSV/Excel files for all types) - case insensitive
    const ext = uploadFile.file.name.split('.').pop()?.toLowerCase();
    const needsMapping = ext === 'csv' || ext === 'xlsx' || ext === 'xls';

    if (needsMapping) {
      // Preview the file for column mapping
      setFiles(prev => {
        const updated = [...prev];
        updated[index] = { ...updated[index], status: 'mapping' };
        return updated;
      });

      // Simulate reading first few rows for preview
      const previewData = await generatePreviewData(uploadFile.file, uploadFile.type);
      
      setFiles(prev => {
        const updated = [...prev];
        updated[index] = { ...updated[index], previewData };
        return updated;
      });

      // Open mapping dialog
      setMappingDialog({ 
        open: true, 
        file: uploadFile.file, 
        fileType: uploadFile.type 
      });
    } else {
      // Direct upload for text config files and JSON files
      await uploadFileDirectly(uploadFile, index);
    }
  };

  const generatePreviewData = async (file: File, type: string): Promise<any[]> => {
    // Simulate CSV parsing for preview
    if (file.name.endsWith('.csv')) {
      if (type === 'firewall') {
        return [
          { 'Source IP': '192.168.1.10', 'Destination IP': '10.0.0.5', 'Port': '80', 'Protocol': 'TCP', 'Action': 'permit' },
          { 'Source IP': '192.168.1.20', 'Destination IP': '10.0.0.10', 'Port': '443', 'Protocol': 'TCP', 'Action': 'permit' }
        ];
      } else if (type === 'cmdb') {
        return [
          { 'Hostname': 'server01', 'IP Address': '192.168.1.10', 'Type': 'Server', 'Owner': 'IT Team' },
          { 'Hostname': 'server02', 'IP Address': '192.168.1.11', 'Type': 'Database', 'Owner': 'DB Team' }
        ];
      } else if (type === 'vlan') {
        return [
          { 'VLAN ID': '100', 'Name': 'Production', 'Subnet': '192.168.100.0/24', 'Gateway': '192.168.100.1' },
          { 'VLAN ID': '200', 'Name': 'Development', 'Subnet': '192.168.200.0/24', 'Gateway': '192.168.200.1' }
        ];
      } else {
        return [
          { 'Name': 'WebServers', 'Type': 'subnet', 'Interface': 'inside', 'Details': 'Prod web servers', 'IP': '10.10.10.0/24' },
          { 'Name': 'DBCluster', 'Type': 'host', 'Interface': 'db', 'Details': 'Primary DB', 'IP': '10.10.20.11' }
        ];
      }
    }
    return [];
  };

  const handleColumnMapping = async (mapping: { [key: string]: string | string[] }) => {
    if (!mappingDialog.file) return;

    const fileIndex = files.findIndex(f => f.name === mappingDialog.file!.name);
    if (fileIndex === -1) return;

    // Save mapping and upload
    setFiles(prev => {
      const updated = [...prev];
      updated[fileIndex] = { 
        ...updated[fileIndex], 
        columnMapping: mapping as any,
        status: 'uploading'
      };
      return updated;
    });

    await uploadFileDirectly(files[fileIndex], fileIndex, mappingDialog.file!, mapping as any);
    setMappingDialog({ open: false, file: null, fileType: 'firewall' });
  };

  const uploadFileDirectly = async (uploadFile: UploadedFile, index: number, fileOverride?: File, columnMappingOverride?: { [key: string]: any }) => {
    if (!uploadFile.file && !fileOverride) return;
    let progressInterval: any;
    try {
      setFiles(prev => {
        const updated = [...prev];
        updated[index] = { ...updated[index], status: 'uploading', progress: 0 };
        return updated;
      });

      // Simulate upload progress
      progressInterval = setInterval(() => {
        setFiles(prev => {
          const updated = [...prev];
          if (updated[index] && updated[index].progress < 90) {
            updated[index].progress += 10;
          }
          return updated;
        });
      }, 200);

      // Actual upload
      const response = await apiService.uploadFile(
        fileOverride || (uploadFile.file as File),
        uploadFile.type,
        columnMappingOverride || uploadFile.columnMapping
      );
      
      setFiles(prev => {
        const updated = [...prev];
        updated[index] = { 
          ...updated[index], 
          status: 'success', 
          progress: 100 
        };
        return updated;
      });
      
      // Show success message with refresh suggestion
      alert(`File uploaded successfully! Please refresh the Rules page to see the updated data with proper column mapping.`);

    } catch (error: any) {
      const serverMsg = error?.response?.data?.message || error?.response?.data?.error;
      const errText = serverMsg || (error instanceof Error ? error.message : 'Upload failed');
      setFiles(prev => {
        const updated = [...prev];
        updated[index] = { 
          ...updated[index], 
          status: 'error', 
          error: errText
        };
        return updated;
      });
    } finally {
      if (progressInterval) clearInterval(progressInterval);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success':
        return <SuccessIcon color="success" />;
      case 'error':
        return <ErrorIcon color="error" />;
      case 'mapping':
        return <SettingsIcon color="warning" />;
      default:
        return <FileIcon />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'firewall':
        return 'error';
      case 'cmdb':
        return 'primary';
      case 'vlan':
        return 'secondary';
      case 'objects':
        return 'success';
      default:
        return 'default';
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'firewall':
        return 'Firewall Config';
      case 'cmdb':
        return 'CMDB Assets';
      case 'vlan':
        return 'VLAN Networks';
      case 'objects':
        return 'Objects';
      default:
        return 'Unknown';
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        File Uploads
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Upload firewall configurations, CMDB data, and VLAN information for analysis.
      </Typography>

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 8 }}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Select File Type
              </Typography>
              <FormControl fullWidth>
                <InputLabel>File Type</InputLabel>
                <Select
                  value={selectedFileType}
                  label="File Type"
                  onChange={(e) => setSelectedFileType(e.target.value as any)}
                >
                  <MenuItem value="firewall">Firewall Configuration</MenuItem>
                  <MenuItem value="cmdb">CMDB Assets</MenuItem>
                  <MenuItem value="vlan">VLAN Networks</MenuItem>
                  <MenuItem value="objects">Objects</MenuItem>
                </Select>
              </FormControl>
            </CardContent>
          </Card>

          <Paper
            sx={{
              p: 4,
              border: dragOver ? '2px dashed #1976d2' : '2px dashed #ccc',
              backgroundColor: dragOver ? '#f5f5f5' : 'transparent',
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
            }}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <UploadIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              Drag and drop {getTypeLabel(selectedFileType).toLowerCase()} files here
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              or click to select files
            </Typography>
            <input
              type="file"
              multiple
              onChange={handleFileSelect}
              style={{ display: 'none' }}
              id="file-upload"
              accept={selectedFileType === 'firewall' ? '.txt,.conf,.csv,.xlsx,.xls,.json' : '.csv,.xlsx,.xls,.json'}
            />
            <label htmlFor="file-upload">
              <Button variant="contained" component="span" startIcon={<UploadIcon />}>
                Select {getTypeLabel(selectedFileType)} Files
              </Button>
            </label>
          </Paper>

          {files.length > 0 && (
            <Paper sx={{ mt: 3 }}>
              <Typography variant="h6" sx={{ p: 2, borderBottom: '1px solid #eee' }}>
                Uploaded Files
              </Typography>
              <List>
                {files.map((file, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      {getStatusIcon(file.status)}
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body1">{file.name}</Typography>
                          <Chip
                            label={getTypeLabel(file.type)}
                            size="small"
                            color={getTypeColor(file.type) as any}
                          />
                          {file.status === 'mapping' && (
                            <Chip
                              label="Needs Column Mapping"
                              size="small"
                              color="warning"
                              icon={<SettingsIcon />}
                            />
                          )}
                        </Box>
                      }
                      secondary={
                        <Box component="span">
                          <Typography variant="body2" color="text.secondary" component="span">
                            {formatFileSize(file.size)}
                          </Typography>
                          {file.status === 'uploading' && (
                            <Box component="span" sx={{ display: 'block', mt: 1 }}>
                              <LinearProgress
                                variant="determinate"
                                value={file.progress}
                              />
                            </Box>
                          )}
                        </Box>
                      }
                    />
                    {/* Move Alert components outside ListItemText to avoid nesting div within p */}
                    {file.error && (
                      <Box sx={{ mt: 1, ml: 7 }}>
                        <Alert severity="error">
                          {file.error}
                        </Alert>
                      </Box>
                    )}
                    {file.status === 'mapping' && (
                      <Box sx={{ mt: 1, ml: 7 }}>
                        <Alert severity="info">
                          Column mapping required before upload can proceed.
                        </Alert>
                      </Box>
                    )}
                    {file.status === 'mapping' && (
                      <IconButton
                        size="small"
                        onClick={() => setMappingDialog({ 
                          open: true, 
                          file: file.file || null, 
                          fileType: file.type 
                        })}
                        disabled={false}
                      >
                        <SmartIcon />
                      </IconButton>
                    )}
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Grid>

        <Grid size={{ xs: 12, md: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                File Type Information
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Chip label="Firewall Config" color="error" sx={{ mr: 1, mb: 1 }} />
                <Typography variant="body2" color="text.secondary">
                  .txt, .conf, .csv, .xlsx, .xls, .json files containing firewall rules and ACLs
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Chip label="CMDB Assets" color="primary" sx={{ mr: 1, mb: 1 }} />
                <Typography variant="body2" color="text.secondary">
                  .csv, .xlsx, .xls files with asset inventory data
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Chip label="VLAN Networks" color="secondary" sx={{ mr: 1, mb: 1 }} />
                <Typography variant="body2" color="text.secondary">
                  .csv, .xlsx, .xls files with network and VLAN information
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Chip label="Objects" color="success" sx={{ mr: 1, mb: 1 }} />
                <Typography variant="body2" color="text.secondary">
                  .csv, .xlsx, .xls files with object data: Name, Type, Interface, Details, IP
                </Typography>
              </Box>
            </CardContent>
          </Card>

          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Upload Process
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                1. Select the appropriate file type above
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                2. Upload your files (max 64MB each)
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                3. For CSV/Excel files, map columns to system fields
              </Typography>
              <Typography variant="body2" color="text.secondary">
                4. Files are automatically parsed and stored
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <EnhancedColumnMappingDialog
          open={mappingDialog.open}
          file={mappingDialog.file}
          fileType={mappingDialog.fileType}
          onClose={() => setMappingDialog({ open: false, file: null, fileType: 'firewall' })}
          onSave={(mapping) => { void handleColumnMapping(mapping as any); }}
        />
    </Box>
  );
};

export default Uploads;
