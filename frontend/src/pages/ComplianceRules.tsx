import React, { useState, useEffect } from 'react';
import ConditionTreeEditor from '../components/ConditionTreeEditor';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  OutlinedInput,
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
  Tooltip,
  Typography,
  Alert,
  SelectChangeEvent
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Security as SecurityIcon,
  Rule as RuleIcon,
  Sync as SyncIcon
} from '@mui/icons-material';

interface ComplianceRule {
  id: number;
  rule_name: string;
  description: string;
  field_to_check: string;
  operator: string;
  value: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  is_active: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

interface ComplianceField {
  name: string;
  type: string;
  description: string;
}

interface ComplianceOperator {
  name: string;
  description: string;
}

type SeverityType = 'Low' | 'Medium' | 'High' | 'Critical';

const ComplianceRules: React.FC = () => {
  const [rules, setRules] = useState<ComplianceRule[]>([]);
  const [fields, setFields] = useState<ComplianceField[]>([]);
  const [operators, setOperators] = useState<ComplianceOperator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [totalCount, setTotalCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [dialogMode, setDialogMode] = useState<'create' | 'edit' | 'view'>('create');
  const [selectedRule, setSelectedRule] = useState<ComplianceRule | null>(null);
  
  // Form state
  const [formData, setFormData] = useState({
    rule_name: '',
    description: '',
    field_to_check: '',
    operator: '',
    value: '',
    severity: 'Medium' as SeverityType,
    is_active: true,
    created_by: 'admin'
  });
  const [multiMode, setMultiMode] = useState(false);
  const [logicOp, setLogicOp] = useState<'AND' | 'OR'>('AND');
  const [conditions, setConditions] = useState<Array<{ field: string; operator: string; value: string; not?: boolean }>>([]);
  const [compositeJson, setCompositeJson] = useState<string>('');

  useEffect(() => {
    fetchFields();
    fetchOperators();
  }, []);

  useEffect(() => {
    if (openDialog && (fields.length === 0 || operators.length === 0)) {
      fetchFields();
      fetchOperators();
    }
  }, [openDialog]);

  useEffect(() => {
    const debounceFetch = setTimeout(() => {
      fetchRules();
    }, 500); // 500ms debounce

    return () => clearTimeout(debounceFetch);
  }, [page, rowsPerPage, searchQuery]);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        `http://localhost:5001/api/compliance-rules?page=${page + 1}&per_page=${rowsPerPage}&search=${searchQuery}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch compliance rules');
      }
      
      const data = await response.json();
      setRules(data.rules || []);
      setTotalCount(data.total_items || 0);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch compliance rules');
    } finally {
      setLoading(false);
    }
  };

  const fetchFields = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/compliance/fields');
      if (!response.ok) throw new Error('Failed to fetch fields');
      const data = await response.json();
      setFields(data.fields || []);
    } catch (err) {
      console.error('Error fetching fields:', err);
    }
  };

  const fetchOperators = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/compliance/operators');
      if (!response.ok) throw new Error('Failed to fetch operators');
      const data = await response.json();
      setOperators(data.operators || []);
    } catch (err) {
      console.error('Error fetching operators:', err);
    }
  };

  const handleSyncCustomRules = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:5001/api/custom-rules/sync', {
        method: 'POST'
      });
      if (!response.ok) {
        throw new Error('Failed to sync custom rules');
      }
      const data = await response.json();
      setSuccess(data.message || 'Custom rules synced successfully');
      setError(null);
      await fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to sync custom rules');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRule = () => {
    setDialogMode('create');
    setSelectedRule(null);
    setFormData({
      rule_name: '',
      description: '',
      field_to_check: '',
      operator: '',
      value: '',
      severity: 'Medium',
      is_active: true,
      created_by: 'admin'
    });
    setOpenDialog(true);
    setCompositeJson(JSON.stringify({ logic: 'AND', conditions: [] }));
  };

  const handleEditRule = (rule: ComplianceRule) => {
    setDialogMode('edit');
    setSelectedRule(rule);
    setFormData({
      rule_name: rule.rule_name,
      description: rule.description,
      field_to_check: rule.field_to_check,
      operator: rule.operator,
      value: rule.value,
      severity: rule.severity,
      is_active: rule.is_active,
      created_by: rule.created_by
    });
    try {
      if (rule.operator === 'composite' && rule.value) {
        setMultiMode(true);
        setCompositeJson(rule.value);
      } else {
        setMultiMode(false);
        setLogicOp('AND');
        setConditions([]);
        setCompositeJson('');
      }
    } catch {
      setMultiMode(false);
      setLogicOp('AND');
      setConditions([]);
      setCompositeJson('');
    }
    setOpenDialog(true);
  };

  const handleViewRule = (rule: ComplianceRule) => {
    setDialogMode('view');
    setSelectedRule(rule);
    setFormData({
      rule_name: rule.rule_name,
      description: rule.description,
      field_to_check: rule.field_to_check,
      operator: rule.operator,
      value: rule.value,
      severity: rule.severity,
      is_active: rule.is_active,
      created_by: rule.created_by
    });
    try {
      if (rule.operator === 'composite' && rule.value) {
        setMultiMode(true);
        setCompositeJson(rule.value);
      } else {
        setMultiMode(false);
        setCompositeJson('');
      }
    } catch {
      setMultiMode(false);
      setCompositeJson('');
    }
    setOpenDialog(true);
  };

  const handleDeleteRule = async (ruleId: number) => {
    if (!window.confirm('Are you sure you want to delete this compliance rule?')) {
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/api/compliance-rules/${ruleId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete compliance rule');
      }

      setSuccess('Compliance rule deleted successfully');
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete compliance rule');
    }
  };

  const handleSubmit = async () => {
    try {
      const url = dialogMode === 'create' 
        ? 'http://localhost:5001/api/compliance-rules'
        : `http://localhost:5001/api/compliance-rules/${selectedRule?.id}`;
      
      const method = dialogMode === 'create' ? 'POST' : 'PUT';
      
      let payload: any = { ...formData };
      if (multiMode) {
        payload = {
          rule_name: formData.rule_name,
          description: formData.description,
          field_to_check: '__composite__',
          operator: 'composite',
          value: compositeJson || JSON.stringify({ logic: 'AND', conditions: [] }),
          severity: formData.severity,
          is_active: formData.is_active,
          created_by: formData.created_by
        };
      }
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Failed to ${dialogMode} compliance rule`);
      }

      setSuccess(`Compliance rule ${dialogMode === 'create' ? 'created' : 'updated'} successfully`);
      setOpenDialog(false);
      fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${dialogMode} compliance rule`);
    }
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'error';
      case 'High': return 'warning';
      case 'Medium': return 'info';
      case 'Low': return 'success';
      default: return 'default';
    }
  };

  const getFieldDescription = (fieldName: string) => {
    const field = fields.find(f => f.name === fieldName);
    return field?.description || fieldName;
  };

  const getOperatorDescription = (operatorName: string) => {
    const operator = operators.find(o => o.name === operatorName);
    return operator?.description || operatorName;
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SecurityIcon sx={{ fontSize: 32, color: 'primary.main' }} />
          <Typography variant="h4" component="h1">
            Compliance Rules
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<SyncIcon />}
            onClick={handleSyncCustomRules}
            sx={{ borderRadius: 2 }}
          >
            Sync Custom Rules
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleCreateRule}
            sx={{ borderRadius: 2 }}
          >
            Create Rule
          </Button>
        </Box>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Stats Cards */}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 3 }}>
        <Box sx={{ flex: '1 1 250px', minWidth: '200px' }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <RuleIcon sx={{ color: 'primary.main' }} />
                <Box>
                  <Typography variant="h6">{totalCount}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Rules
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
        <Box sx={{ flex: '1 1 250px', minWidth: '200px' }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SecurityIcon sx={{ color: 'success.main' }} />
                <Box>
                  <Typography variant="h6">
                    {rules.filter(r => r.is_active).length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Active Rules
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
        <Box sx={{ flex: '1 1 250px', minWidth: '200px' }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SecurityIcon sx={{ color: 'error.main' }} />
                <Box>
                  <Typography variant="h6">
                    {rules.filter(r => r.severity === 'Critical' || r.severity === 'High').length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    High Priority
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
        <Box sx={{ flex: '1 1 250px', minWidth: '200px' }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SecurityIcon sx={{ color: 'info.main' }} />
                <Box>
                  <Typography variant="h6">{fields.length}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Available Fields
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Box>

      {/* Rules Table */}
      <Paper sx={{ borderRadius: 2 }}>
        <Box sx={{ p: 2 }}>
          <TextField
            fullWidth
            variant="outlined"
            label="Search Rules"
            placeholder="Search by name or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </Box>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Rule Name</TableCell>
                <TableCell>Field</TableCell>
                <TableCell>Operator</TableCell>
                <TableCell>Value</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Created By</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    Loading...
                  </TableCell>
                </TableRow>
              ) : rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    <Box sx={{ py: 3 }}>
                      <Typography variant="body1" sx={{ mb: 1 }}>
                        No compliance rules found.
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        Create a rule or sync from Custom Rules.
                      </Typography>
                      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1 }}>
                        <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreateRule}>
                          Create Rule
                        </Button>
                        <Button variant="outlined" startIcon={<SyncIcon />} onClick={handleSyncCustomRules}>
                          Sync Custom Rules
                        </Button>
                      </Box>
                    </Box>
                  </TableCell>
                </TableRow>
              ) : (
                rules.map((rule) => (
                  <TableRow key={rule.id} hover>
                    <TableCell>
                      <Typography variant="subtitle2">{rule.rule_name}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {rule.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={getFieldDescription(rule.field_to_check)}>
                        <Chip 
                          label={rule.field_to_check} 
                          size="small" 
                          variant="outlined"
                        />
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={getOperatorDescription(rule.operator)}>
                        <Chip 
                          label={rule.operator} 
                          size="small" 
                          color="primary"
                          variant="outlined"
                        />
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {rule.value}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={rule.severity} 
                        color={getSeverityColor(rule.severity) as any}
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
                    <TableCell>{rule.created_by}</TableCell>
                    <TableCell align="center">
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="View">
                          <IconButton 
                            size="small" 
                            onClick={() => handleViewRule(rule)}
                          >
                            <ViewIcon />
                          </IconButton>
                        </Tooltip>
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
                            color="error"
                            onClick={() => handleDeleteRule(rule.id)}
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
        </TableContainer>
        
        <TablePagination
          component="div"
          count={totalCount}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(event) => {
            setRowsPerPage(parseInt(event.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[5, 10, 25, 50]}
        />
      </Paper>

      {/* Create/Edit Dialog */}
      <Dialog 
        open={openDialog} 
        onClose={() => setOpenDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {dialogMode === 'create' ? 'Create Compliance Rule' : 
           dialogMode === 'edit' ? 'Edit Compliance Rule' : 'View Compliance Rule'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <Box>
                <TextField
                  fullWidth
                  label="Rule Name"
                  value={formData.rule_name}
                  onChange={(e) => handleInputChange('rule_name', e.target.value)}
                  disabled={dialogMode === 'view'}
                  required
                />
              </Box>
              
              <Box>
                <TextField
                  fullWidth
                  label="Description"
                  value={formData.description}
                  onChange={(e) => handleInputChange('description', e.target.value)}
                  disabled={dialogMode === 'view'}
                  multiline
                  rows={3}
                />
              </Box>
              
              <Box sx={{ display: 'flex', gap: 2, flexDirection: { xs: 'column', sm: 'row' } }}>
                <Box sx={{ flex: 1 }}>
                  <FormControl fullWidth required>
                    <InputLabel>Field to Check</InputLabel>
                    <Select
                      value={multiMode ? '__composite__' : formData.field_to_check}
                      onChange={(e: SelectChangeEvent) => handleInputChange('field_to_check', e.target.value)}
                      disabled={dialogMode === 'view' || multiMode}
                      label="Field to Check"
                    >
                      {fields.map((field) => (
                        <MenuItem key={field.name} value={field.name}>
                          <Box>
                            <Typography variant="body2">{field.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {field.description}
                            </Typography>
                          </Box>
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Box>
                
                <Box sx={{ flex: 1 }}>
                  <FormControl fullWidth required>
                    <InputLabel>Operator</InputLabel>
                    <Select
                      value={multiMode ? 'composite' : formData.operator}
                      onChange={(e: SelectChangeEvent) => {
                        const op = e.target.value as string;
                        if (op === 'composite') {
                          setMultiMode(true);
                          setFormData(prev => ({ ...prev, field_to_check: '__composite__' }));
                        } else {
                          setMultiMode(false);
                          handleInputChange('operator', op);
                        }
                      }}
                      disabled={dialogMode === 'view'}
                      label="Operator"
                    >
                      {operators.map((operator) => (
                        <MenuItem key={operator.name} value={operator.name}>
                          <Box>
                            <Typography variant="body2">{operator.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {operator.description}
                            </Typography>
                          </Box>
                        </MenuItem>
                      ))}
                      <MenuItem value="composite">
                        <Box>
                          <Typography variant="body2">composite</Typography>
                          <Typography variant="caption" color="text.secondary">
                            Multiple conditions with AND/OR/NOT
                          </Typography>
                        </Box>
                      </MenuItem>
                    </Select>
                  </FormControl>
                </Box>
              </Box>
              
              <Box>
                {multiMode ? (
                  <ConditionTreeEditor
                    value={compositeJson}
                    fields={fields}
                    operators={operators}
                    readOnly={dialogMode === 'view'}
                    onChange={(v) => setCompositeJson(v)}
                  />
                ) : (
                  <TextField
                    fullWidth
                    label="Value"
                    value={formData.value}
                    onChange={(e) => handleInputChange('value', e.target.value)}
                    disabled={dialogMode === 'view'}
                    required
                    helperText="For list operators, use comma-separated values (e.g., TCP/21, TCP/23, TCP/80)"
                  />
                )}
              </Box>

              {dialogMode === 'view' && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Rule Structure</Typography>
                  {!multiMode ? (
                    <TableContainer component={Paper} sx={{ mt: 1 }}>
                      <Table size="small">
                        <TableBody>
                          <TableRow>
                            <TableCell>Field Checked</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{formData.field_to_check}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Operator</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{formData.operator}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Expected Value</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{formData.value}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Severity</TableCell>
                            <TableCell>{formData.severity}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Status</TableCell>
                            <TableCell>{formData.is_active ? 'Active' : 'Inactive'}</TableCell>
                          </TableRow>
                        </TableBody>
                      </Table>
                    </TableContainer>
                  ) : (
                    (() => {
                      try {
                        const obj = JSON.parse(compositeJson || '{}');
                        const conds = Array.isArray(obj.conditions) ? obj.conditions : [];
                        return (
                          <TableContainer component={Paper} sx={{ mt: 1 }}>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Group Logic</TableCell>
                                  <TableCell>Field</TableCell>
                                  <TableCell>Operator</TableCell>
                                  <TableCell>Value</TableCell>
                                  <TableCell>Not</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {conds.length === 0 ? (
                                  <TableRow>
                                    <TableCell colSpan={5}>No conditions</TableCell>
                                  </TableRow>
                                ) : (
                                  conds.map((c: any, idx: number) => (
                                    <TableRow key={idx}>
                                      <TableCell>{String(obj.logic || 'AND')}</TableCell>
                                      <TableCell sx={{ wordBreak: 'break-word' }}>{String(c.field || '')}</TableCell>
                                      <TableCell sx={{ wordBreak: 'break-word' }}>{String(c.operator || '')}</TableCell>
                                      <TableCell sx={{ wordBreak: 'break-word' }}>{typeof c.value === 'object' ? JSON.stringify(c.value) : String(c.value || '')}</TableCell>
                                      <TableCell>{c.not ? 'true' : 'false'}</TableCell>
                                    </TableRow>
                                  ))
                                )}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        );
                      } catch (e) {
                        return <Alert severity="warning" sx={{ mt: 1 }}>Invalid composite JSON</Alert>;
                      }
                    })()
                  )}
                </Box>
              )}

              {multiMode && (<Box sx={{ mt: 2 }} />)}
              
              <Box sx={{ display: 'flex', gap: 2, flexDirection: { xs: 'column', sm: 'row' } }}>
                <Box sx={{ flex: 1 }}>
                  <FormControl fullWidth required>
                    <InputLabel>Severity</InputLabel>
                    <Select
                      value={formData.severity}
                      onChange={(e: SelectChangeEvent) => handleInputChange('severity', e.target.value)}
                      disabled={dialogMode === 'view'}
                      label="Severity"
                    >
                      <MenuItem value="Low">Low</MenuItem>
                      <MenuItem value="Medium">Medium</MenuItem>
                      <MenuItem value="High">High</MenuItem>
                      <MenuItem value="Critical">Critical</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
                
                <Box sx={{ flex: 1 }}>
                  <FormControl fullWidth>
                    <InputLabel>Status</InputLabel>
                    <Select
                      value={formData.is_active ? 'active' : 'inactive'}
                      onChange={(e: SelectChangeEvent) => handleInputChange('is_active', e.target.value === 'active')}
                      disabled={dialogMode === 'view'}
                      label="Status"
                    >
                      <MenuItem value="active">Active</MenuItem>
                      <MenuItem value="inactive">Inactive</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
              </Box>

              {dialogMode !== 'view' && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Preview</Typography>
                  {!multiMode ? (
                    <TableContainer component={Paper} sx={{ mt: 1 }}>
                      <Table size="small">
                        <TableBody>
                          <TableRow>
                            <TableCell>Field Checked</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{formData.field_to_check}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Operator</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{formData.operator}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Operator Description</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{
                              (() => {
                                const op = operators.find(o => o.name === formData.operator);
                                return op ? op.description : '';
                              })()
                            }</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Field Description</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{
                              (() => {
                                const f = fields.find(fl => fl.name === formData.field_to_check);
                                return f ? f.description : '';
                              })()
                            }</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Expected Value</TableCell>
                            <TableCell sx={{ wordBreak: 'break-word' }}>{formData.value}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Severity</TableCell>
                            <TableCell>{formData.severity}</TableCell>
                          </TableRow>
                          <TableRow>
                            <TableCell>Status</TableCell>
                            <TableCell>{formData.is_active ? 'Active' : 'Inactive'}</TableCell>
                          </TableRow>
                        </TableBody>
                      </Table>
                    </TableContainer>
                  ) : (
                    (() => {
                      try {
                        const obj = JSON.parse(compositeJson || '{}');
                        const conds = Array.isArray(obj.conditions) ? obj.conditions : [];
                        return (
                          <TableContainer component={Paper} sx={{ mt: 1 }}>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Group Logic</TableCell>
                                  <TableCell>Field</TableCell>
                                  <TableCell>Operator</TableCell>
                                  <TableCell>Value</TableCell>
                                  <TableCell>Not</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {conds.length === 0 ? (
                                  <TableRow>
                                    <TableCell colSpan={5}>No conditions</TableCell>
                                  </TableRow>
                                ) : (
                                  conds.map((c: any, idx: number) => (
                                    <TableRow key={idx}>
                                      <TableCell>{String(obj.logic || 'AND')}</TableCell>
                                      <TableCell sx={{ wordBreak: 'break-word' }}>{String(c.field || '')}</TableCell>
                                      <TableCell sx={{ wordBreak: 'break-word' }}>{String(c.operator || '')}</TableCell>
                                      <TableCell sx={{ wordBreak: 'break-word' }}>{typeof c.value === 'object' ? JSON.stringify(c.value) : String(c.value || '')}</TableCell>
                                      <TableCell>{c.not ? 'true' : 'false'}</TableCell>
                                    </TableRow>
                                  ))
                                )}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        );
                      } catch (e) {
                        return <Alert severity="warning" sx={{ mt: 1 }}>Invalid composite JSON</Alert>;
                      }
                    })()
                  )}
                </Box>
              )}
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>
            Cancel
          </Button>
          {dialogMode !== 'view' && (
            <Button 
              onClick={handleSubmit} 
              variant="contained"
            >
              {dialogMode === 'create' ? 'Create' : 'Update'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ComplianceRules;
