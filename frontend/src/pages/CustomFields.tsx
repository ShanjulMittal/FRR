import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography,
  Chip,
  Alert,
  Tooltip,
  SelectChangeEvent,
  Checkbox,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Divider,
  OutlinedInput,
  Switch,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Settings as SettingsIcon,
  Rule as RuleIcon,
  Analytics as AnalyticsIcon,
} from '@mui/icons-material';
import api from '../services/api';

type FieldType = 'text' | 'number' | 'boolean' | 'date' | 'select';
type FileType = 'firewall' | 'cmdb' | 'vlan';
type ConditionType = 'threshold' | 'range' | 'pattern' | 'custom';
type ActionType = 'alert' | 'block' | 'flag' | 'log';
type SeverityType = 'low' | 'medium' | 'high' | 'critical';

interface CustomField {
  id: number;
  field_name: string;
  display_name: string;
  description: string;
  field_type: FieldType;
  file_type: FileType;
  is_mandatory: boolean;
  is_important: boolean;
  default_value?: string;
  validation_rules?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  is_active: boolean;
}

interface CustomRule {
  id: number;
  field_id: number;
  rule_name: string;
  description: string;
  condition_type: ConditionType;
  condition_value: string;
  action: ActionType;
  severity: SeverityType;
  is_active: boolean;
  created_by: string;
  created_at: string;
}

const CustomFields: React.FC = () => {
  const [fields, setFields] = useState<CustomField[]>([]);
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [openFieldDialog, setOpenFieldDialog] = useState(false);
  const [openRuleDialog, setOpenRuleDialog] = useState(false);
  const [selectedField, setSelectedField] = useState<CustomField | null>(null);
  const [selectedRule, setSelectedRule] = useState<CustomRule | null>(null);
  const [dialogMode, setDialogMode] = useState<'create' | 'edit' | 'view'>('create');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [activeTab, setActiveTab] = useState<'fields' | 'rules'>('fields');

  // Field form data
  const [fieldFormData, setFieldFormData] = useState({
    field_name: '',
    display_name: '',
    description: '',
    field_type: 'text' as FieldType,
    file_type: 'firewall' as FileType,
    is_mandatory: false,
    is_important: false,
    default_value: '',
    validation_rules: '',
    is_active: true,
  });

  // Rule form data
  const [ruleFormData, setRuleFormData] = useState({
    field_id: 0,
    rule_name: '',
    description: '',
    condition_type: 'threshold' as ConditionType,
    condition_value: '',
    action: 'alert' as ActionType,
    severity: 'medium' as SeverityType,
    is_active: true,
  });

  useEffect(() => {
    fetchFields();
    fetchRules();
  }, []);

  const fetchFields = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/custom-fields');
      setFields(response.data.data || []);
    } catch (error) {
      console.error('Error fetching custom fields:', error);
      setFields([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchRules = async () => {
    try {
      const response = await api.get('/api/custom-rules');
      setRules(response.data.data || []);
    } catch (error) {
      console.error('Error fetching custom rules:', error);
      setRules([]);
    }
  };

  const handleCreateField = () => {
    setDialogMode('create');
    setSelectedField(null);
    setFieldFormData({
      field_name: '',
      display_name: '',
      description: '',
      field_type: 'text',
      file_type: 'firewall',
      is_mandatory: false,
      is_important: false,
      default_value: '',
      validation_rules: '',
      is_active: true,
    });
    setOpenFieldDialog(true);
  };

  const handleEditField = (field: CustomField) => {
    setDialogMode('edit');
    setSelectedField(field);
    setFieldFormData({
      field_name: field.field_name,
      display_name: field.display_name,
      description: field.description,
      field_type: field.field_type,
      file_type: field.file_type,
      is_mandatory: field.is_mandatory,
      is_important: field.is_important,
      default_value: field.default_value || '',
      validation_rules: field.validation_rules || '',
      is_active: field.is_active,
    });
    setOpenFieldDialog(true);
  };

  const handleCreateRule = () => {
    setDialogMode('create');
    setSelectedRule(null);
    setRuleFormData({
      field_id: 0,
      rule_name: '',
      description: '',
      condition_type: 'threshold',
      condition_value: '',
      action: 'alert',
      severity: 'medium',
      is_active: true,
    });
    setOpenRuleDialog(true);
  };

  const handleEditRule = (rule: CustomRule) => {
    setDialogMode('edit');
    setSelectedRule(rule);
    setRuleFormData({
      field_id: rule.field_id,
      rule_name: rule.rule_name,
      description: rule.description,
      condition_type: rule.condition_type,
      condition_value: rule.condition_value,
      action: rule.action,
      severity: rule.severity,
      is_active: rule.is_active,
    });
    setOpenRuleDialog(true);
  };

  const handleSubmitField = async () => {
    try {
      const url = dialogMode === 'create' ? '/api/custom-fields' : `/api/custom-fields/${selectedField?.id}`;
      
      if (dialogMode === 'create') {
        await api.post(url, {
          ...fieldFormData,
          created_by: 'admin', // This should come from auth context
        });
      } else {
        await api.put(url, {
          ...fieldFormData,
          created_by: 'admin', // This should come from auth context
        });
      }

      setOpenFieldDialog(false);
      fetchFields();
    } catch (error) {
      console.error('Error saving field:', error);
    }
  };

  const handleSubmitRule = async () => {
    try {
      const url = dialogMode === 'create' ? '/api/custom-rules' : `/api/custom-rules/${selectedRule?.id}`;
      
      if (dialogMode === 'create') {
        await api.post(url, {
          ...ruleFormData,
          created_by: 'admin', // This should come from auth context
        });
      } else {
        await api.put(url, {
          ...ruleFormData,
          created_by: 'admin', // This should come from auth context
        });
      }

      setOpenRuleDialog(false);
      fetchRules();
    } catch (error) {
      console.error('Error saving rule:', error);
    }
  };

  const handleDeleteField = async (field: CustomField) => {
    if (window.confirm(`Are you sure you want to delete the field "${field.display_name}"?`)) {
      try {
        await api.delete(`/api/custom-fields/${field.id}`);
        fetchFields();
      } catch (error) {
        console.error('Error deleting field:', error);
      }
    }
  };

  const handleDeleteRule = async (rule: CustomRule) => {
    if (window.confirm(`Are you sure you want to delete the rule "${rule.rule_name}"?`)) {
      try {
        await api.delete(`/api/custom-rules/${rule.id}`);
        fetchRules();
      } catch (error) {
        console.error('Error deleting rule:', error);
      }
    }
  };

  const getFieldTypeColor = (type: string) => {
    const colors: { [key: string]: 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' } = {
      text: 'default',
      number: 'primary',
      boolean: 'secondary',
      date: 'info',
      select: 'warning',
    };
    return colors[type] || 'default';
  };

  const getSeverityColor = (severity: string) => {
    const colors: { [key: string]: 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' } = {
      low: 'info',
      medium: 'warning',
      high: 'error',
      critical: 'error',
    };
    return colors[severity] || 'default';
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Custom Fields & Rules Management
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Configure custom fields for data mapping and create rules for analysis like hit count thresholds.
      </Typography>

      {/* Tab Navigation */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant={activeTab === 'fields' ? 'contained' : 'outlined'}
            onClick={() => setActiveTab('fields')}
            startIcon={<SettingsIcon />}
          >
            Custom Fields
          </Button>
          <Button
            variant={activeTab === 'rules' ? 'contained' : 'outlined'}
            onClick={() => setActiveTab('rules')}
            startIcon={<RuleIcon />}
          >
            Custom Rules
          </Button>
        </Box>
      </Box>

      {/* Fields Tab */}
      {activeTab === 'fields' && (
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Custom Fields</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={handleCreateField}
              >
                Add Custom Field
              </Button>
            </Box>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Field Name</TableCell>
                    <TableCell>Display Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>File Type</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(fields || [])
                    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                    .map((field) => (
                      <TableRow key={field.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {field.field_name}
                          </Typography>
                        </TableCell>
                        <TableCell>{field.display_name}</TableCell>
                        <TableCell>
                          <Chip
                            label={field.field_type}
                            color={getFieldTypeColor(field.field_type)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip label={field.file_type} size="small" />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                            {field.is_mandatory && (
                              <Chip label="Mandatory" color="error" size="small" />
                            )}
                            {field.is_important && (
                              <Chip label="Important" color="warning" size="small" />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={field.is_active ? 'Active' : 'Inactive'}
                            color={field.is_active ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title="Edit">
                              <IconButton
                                size="small"
                                onClick={() => handleEditField(field)}
                              >
                                <EditIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete">
                              <IconButton
                                size="small"
                                onClick={() => handleDeleteField(field)}
                                color="error"
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              rowsPerPageOptions={[5, 10, 25]}
              component="div"
              count={fields?.length || 0}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={(_, newPage) => setPage(newPage)}
              onRowsPerPageChange={(event) => {
                setRowsPerPage(parseInt(event.target.value, 10));
                setPage(0);
              }}
            />
          </CardContent>
        </Card>
      )}

      {/* Rules Tab */}
      {activeTab === 'rules' && (
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Custom Rules</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={handleCreateRule}
              >
                Add Custom Rule
              </Button>
            </Box>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Rule Name</TableCell>
                    <TableCell>Field</TableCell>
                    <TableCell>Condition</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rules.map((rule) => {
                    const field = (fields || []).find(f => f.id === rule.field_id);
                    return (
                      <TableRow key={rule.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {rule.rule_name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {field ? field.display_name : 'Unknown Field'}
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {rule.condition_type}: {rule.condition_value}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={rule.action} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.severity}
                            color={getSeverityColor(rule.severity)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={rule.is_active ? 'Active' : 'Inactive'}
                            color={rule.is_active ? 'success' : 'default'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title="Edit">
                              <IconButton
                                size="small"
                                onClick={() => handleEditRule(rule)}
                              >
                                <EditIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete">
                              <IconButton
                                size="small"
                                onClick={() => handleDeleteRule(rule)}
                                color="error"
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {/* Field Dialog */}
      <Dialog open={openFieldDialog} onClose={() => setOpenFieldDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {dialogMode === 'create' ? 'Add Custom Field' : 'Edit Custom Field'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2 }}>
              <Box sx={{ flex: 1 }}>
                <TextField
                  fullWidth
                  label="Field Name"
                  value={fieldFormData.field_name}
                  onChange={(e) => setFieldFormData({ ...fieldFormData, field_name: e.target.value })}
                  helperText="Internal field name (e.g., hit_count)"
                  required
                />
              </Box>
              <Box sx={{ flex: 1 }}>
                <TextField
                  fullWidth
                  label="Display Name"
                  value={fieldFormData.display_name}
                  onChange={(e) => setFieldFormData({ ...fieldFormData, display_name: e.target.value })}
                  helperText="User-friendly name (e.g., Hit Count)"
                  required
                />
              </Box>
            </Box>

            <TextField
              fullWidth
              label="Description"
              value={fieldFormData.description}
              onChange={(e) => setFieldFormData({ ...fieldFormData, description: e.target.value })}
              multiline
              rows={2}
              helperText="Describe what this field represents"
            />

            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2 }}>
              <Box sx={{ flex: 1 }}>
                <FormControl fullWidth required>
                  <InputLabel>Field Type</InputLabel>
                  <Select
                    value={fieldFormData.field_type}
                    onChange={(e: SelectChangeEvent) => 
                      setFieldFormData({ ...fieldFormData, field_type: e.target.value as any })
                    }
                    label="Field Type"
                  >
                    <MenuItem value="text">Text</MenuItem>
                    <MenuItem value="number">Number</MenuItem>
                    <MenuItem value="boolean">Boolean</MenuItem>
                    <MenuItem value="date">Date</MenuItem>
                    <MenuItem value="select">Select</MenuItem>
                  </Select>
                </FormControl>
              </Box>
              <Box sx={{ flex: 1 }}>
                <FormControl fullWidth required>
                  <InputLabel>File Type</InputLabel>
                  <Select
                    value={fieldFormData.file_type}
                    onChange={(e: SelectChangeEvent) => 
                      setFieldFormData({ ...fieldFormData, file_type: e.target.value as any })
                    }
                    label="File Type"
                  >
                    <MenuItem value="firewall">Firewall</MenuItem>
                    <MenuItem value="cmdb">CMDB</MenuItem>
                    <MenuItem value="vlan">VLAN</MenuItem>
                  </Select>
                </FormControl>
              </Box>
              <Box sx={{ flex: 1 }}>
                <TextField
                  fullWidth
                  label="Default Value"
                  value={fieldFormData.default_value}
                  onChange={(e) => setFieldFormData({ ...fieldFormData, default_value: e.target.value })}
                  helperText="Optional default value"
                />
              </Box>
            </Box>

            <TextField
              fullWidth
              label="Validation Rules"
              value={fieldFormData.validation_rules}
              onChange={(e) => setFieldFormData({ ...fieldFormData, validation_rules: e.target.value })}
              helperText="JSON format validation rules (optional)"
              multiline
              rows={2}
            />

            <Box sx={{ display: 'flex', gap: 2 }}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={fieldFormData.is_mandatory}
                    onChange={(e) => setFieldFormData({ ...fieldFormData, is_mandatory: e.target.checked })}
                  />
                }
                label="Mandatory Field"
              />
              <FormControlLabel
                control={
                  <Checkbox
                    checked={fieldFormData.is_important}
                    onChange={(e) => setFieldFormData({ ...fieldFormData, is_important: e.target.checked })}
                  />
                }
                label="Important Field"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={fieldFormData.is_active}
                    onChange={(e) => setFieldFormData({ ...fieldFormData, is_active: e.target.checked })}
                  />
                }
                label="Active"
              />
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenFieldDialog(false)}>Cancel</Button>
          <Button onClick={handleSubmitField} variant="contained">
            {dialogMode === 'create' ? 'Create' : 'Update'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rule Dialog */}
      <Dialog open={openRuleDialog} onClose={() => setOpenRuleDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {dialogMode === 'create' ? 'Add Custom Rule' : 'Edit Custom Rule'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2 }}>
              <Box sx={{ flex: 1 }}>
                <TextField
                  fullWidth
                  label="Rule Name"
                  value={ruleFormData.rule_name}
                  onChange={(e) => setRuleFormData({ ...ruleFormData, rule_name: e.target.value })}
                  required
                />
              </Box>
              <Box sx={{ flex: 1 }}>
                <FormControl fullWidth required>
                  <InputLabel>Field</InputLabel>
                  <Select
                    value={ruleFormData.field_id.toString()}
                    onChange={(e: SelectChangeEvent) => 
                      setRuleFormData({ ...ruleFormData, field_id: Number(e.target.value) })
                    }
                    label="Field"
                  >
                    {(fields || []).map((field) => (
                      <MenuItem key={field.id} value={field.id}>
                        {field.display_name} ({field.field_name})
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
            </Box>

            <TextField
              fullWidth
              label="Description"
              value={ruleFormData.description}
              onChange={(e) => setRuleFormData({ ...ruleFormData, description: e.target.value })}
              multiline
              rows={2}
            />

            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2, flexWrap: 'wrap' }}>
              <Box sx={{ flex: { xs: '1 1 100%', sm: '1 1 calc(50% - 8px)', md: '1 1 calc(25% - 12px)' } }}>
                <FormControl fullWidth required>
                  <InputLabel>Condition Type</InputLabel>
                  <Select
                    value={ruleFormData.condition_type}
                    onChange={(e: SelectChangeEvent) => 
                      setRuleFormData({ ...ruleFormData, condition_type: e.target.value as any })
                    }
                    label="Condition Type"
                  >
                    <MenuItem value="threshold">Threshold</MenuItem>
                    <MenuItem value="range">Range</MenuItem>
                    <MenuItem value="pattern">Pattern</MenuItem>
                    <MenuItem value="custom">Custom</MenuItem>
                  </Select>
                </FormControl>
              </Box>
              <Box sx={{ flex: { xs: '1 1 100%', sm: '1 1 calc(50% - 8px)', md: '1 1 calc(25% - 12px)' } }}>
                <TextField
                  fullWidth
                  label="Condition Value"
                  value={ruleFormData.condition_value}
                  onChange={(e) => setRuleFormData({ ...ruleFormData, condition_value: e.target.value })}
                  helperText="e.g., >100, 50-200, regex pattern"
                  required
                />
              </Box>
              <Box sx={{ flex: { xs: '1 1 100%', sm: '1 1 calc(50% - 8px)', md: '1 1 calc(25% - 12px)' } }}>
                <FormControl fullWidth required>
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={ruleFormData.action}
                    onChange={(e: SelectChangeEvent) => 
                      setRuleFormData({ ...ruleFormData, action: e.target.value as any })
                    }
                    label="Action"
                  >
                    <MenuItem value="alert">Alert</MenuItem>
                    <MenuItem value="block">Block</MenuItem>
                    <MenuItem value="flag">Flag</MenuItem>
                    <MenuItem value="log">Log</MenuItem>
                  </Select>
                </FormControl>
              </Box>
              <Box sx={{ flex: { xs: '1 1 100%', sm: '1 1 calc(50% - 8px)', md: '1 1 calc(25% - 12px)' } }}>
                <FormControl fullWidth required>
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={ruleFormData.severity}
                    onChange={(e: SelectChangeEvent) => 
                      setRuleFormData({ ...ruleFormData, severity: e.target.value as any })
                    }
                    label="Severity"
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Box>
            </Box>

            <FormControlLabel
              control={
                <Switch
                  checked={ruleFormData.is_active}
                  onChange={(e) => setRuleFormData({ ...ruleFormData, is_active: e.target.checked })}
                />
              }
              label="Active"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenRuleDialog(false)}>Cancel</Button>
          <Button onClick={handleSubmitRule} variant="contained">
            {dialogMode === 'create' ? 'Create' : 'Update'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default CustomFields;