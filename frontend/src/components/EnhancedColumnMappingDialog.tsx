import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  FormControl,
  Select,
  MenuItem,
  Box,
  Chip,
  Alert,
  CircularProgress,
  Tooltip,
  IconButton,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  AutoFixHigh as AutoIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
  Visibility as PreviewIcon,
} from '@mui/icons-material';
import { apiService } from '../services/api';
import api from '../services/api';

interface FieldSuggestion {
  field: string;
  confidence: number;
  reason: string;
}

interface DetectionResult {
  success: boolean;
  detected_fields: { [key: string]: string };
  suggestions: { [key: string]: FieldSuggestion[] };
  preview_data: any[];
  confidence_scores: { [key: string]: number };
  field_priorities: { [key: string]: string };
  mandatory_missing: string[];
  important_missing: string[];
  columns: string[];
  total_rows: number;
  file_type: string;
  is_text_config?: boolean;
  format_info?: any;
  error?: string;
}

interface AvailableField {
  value: string;
  label: string;
  description: string;
  mandatory?: boolean;
  important?: boolean;
  priority?: string;
}

interface EnhancedColumnMappingDialogProps {
  open: boolean;
  file: File | null;
  fileType: 'firewall' | 'cmdb' | 'vlan' | 'objects';
  onClose: () => void;
  onSave: (mapping: { [key: string]: string | string[] }) => void;
}

const EnhancedColumnMappingDialog: React.FC<EnhancedColumnMappingDialogProps> = ({
  open,
  file,
  fileType,
  onClose,
  onSave,
}) => {
  const [loading, setLoading] = useState(false);
  const [detectionResult, setDetectionResult] = useState<DetectionResult | null>(null);
  const [mapping, setMapping] = useState<{ [key: string]: string[] }>({});
  const [availableFields, setAvailableFields] = useState<AvailableField[]>([]);
  const [showPreview, setShowPreview] = useState(true);
  const [autoApplied, setAutoApplied] = useState(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  useEffect(() => {
    if (open && file) {
      analyzeFile();
      fetchAvailableFields();
    }
  }, [open, file, fileType]);

  const analyzeFile = async () => {
    if (!file) return;

    setLoading(true);
    try {
      console.log('=== STARTING FILE ANALYSIS ===');
      console.log('File:', file.name, 'Size:', file.size, 'Type:', file.type);
      console.log('File type parameter:', fileType);
      
      const formData = new FormData();
      formData.append('file', file);
      formData.append('file_type', fileType);

      console.log('FormData created, making API call to /api/analyze-file');
      console.log('API Base URL:', api.defaults.baseURL);

      const response = await api.post('/api/analyze-file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      console.log('=== API RESPONSE RECEIVED ===');
      console.log('Response status:', response.status);
      console.log('Response headers:', response.headers);
      console.log('Response data type:', typeof response.data);
      console.log('Response data keys:', Object.keys(response.data || {}));

      // Parse response data if it's a string
      let parsedData = response.data;
      if (typeof response.data === 'string') {
        try {
          parsedData = JSON.parse(response.data);
          console.log('Successfully parsed JSON string response');
        } catch (e) {
          console.error('Failed to parse JSON string response:', e);
          throw new Error('Invalid JSON response from server');
        }
      }

      const result: DetectionResult = parsedData;
      console.log('=== FULL API RESPONSE ===');
      console.log('Raw response:', response);
      console.log('Response data:', response.data);
      console.log('=== DETECTION RESULT ===');
      console.log('Detection result:', result);
      console.log('Success:', result.success);
      console.log('Detected fields:', result.detected_fields);
      console.log('Detected fields count:', Object.keys(result.detected_fields || {}).length);
      console.log('Columns:', result.columns);
      console.log('Columns count:', result.columns ? result.columns.length : 0);
      console.log('Preview data:', result.preview_data);
      console.log('Preview data length:', result.preview_data ? result.preview_data.length : 'undefined');
      console.log('Total rows:', result.total_rows);
      console.log('=== END DEBUG ===');
      
      console.log('Setting detection result...');
      setDetectionResult(result);
      console.log('Detection result set successfully');

      if (result.success && result.detected_fields) {
        // Auto-apply high-confidence mappings
        const autoMapping: { [key: string]: string[] } = {};
        let hasAutoMappings = false;

        // Sort detected fields by priority: mandatory first, then important, then optional
        const sortedEntries = Object.entries(result.detected_fields).sort(([columnA, fieldA], [columnB, fieldB]) => {
          const priorityA = result.field_priorities?.[columnA] || 'optional';
          const priorityB = result.field_priorities?.[columnB] || 'optional';
          
          const priorityOrder = { 'mandatory': 0, 'important': 1, 'optional': 2 };
          return priorityOrder[priorityA as keyof typeof priorityOrder] - priorityOrder[priorityB as keyof typeof priorityOrder];
        });

        sortedEntries.forEach(([column, field]) => {
          const confidence = result.confidence_scores[column] || 0;
          const priority = result.field_priorities?.[column] || 'optional';
          
          console.log(`Column: ${column}, Field: ${field}, Confidence: ${confidence}, Priority: ${priority}`);
          
          // Apply different confidence thresholds based on priority
          let shouldApply = false;
          if (priority === 'mandatory' && confidence >= 0.05) { // Very low threshold for mandatory fields
            shouldApply = true;
          } else if (priority === 'important' && confidence >= 0.1) { // Low threshold for important fields
            shouldApply = true;
          } else if (priority === 'optional' && confidence >= 0.3) { // Higher threshold for optional fields
            shouldApply = true;
          }
          
          if (shouldApply) {
            autoMapping[column] = [field];
            hasAutoMappings = true;
          }
        });

        if (hasAutoMappings) {
          setMapping(autoMapping);
          setAutoApplied(true);
        }
      }
    } catch (error) {
      console.error('=== API ERROR ===');
      console.error('Error type:', typeof error);
      console.error('Error object:', error);
      
      if (error instanceof Error) {
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
      }
      
      // Check if it's an axios error
      if (error && typeof error === 'object' && 'response' in error) {
        const axiosError = error as any;
        console.error('Axios error response:', axiosError.response);
        console.error('Axios error status:', axiosError.response?.status);
        console.error('Axios error data:', axiosError.response?.data);
        console.error('Axios error config:', axiosError.config);
      }
      
      // Check if it's a network error
      if (error && typeof error === 'object' && 'code' in error) {
        console.error('Network error code:', (error as any).code);
      }
      
      console.error('=== END ERROR DEBUG ===');
      
      setDetectionResult({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to analyze file',
        detected_fields: {},
        suggestions: {},
        preview_data: [],
        confidence_scores: {},
        field_priorities: {},
        mandatory_missing: [],
        important_missing: [],
        columns: [],
        total_rows: 0,
        file_type: fileType
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchAvailableFields = async () => {
    try {
      // Fetch both standard fields and custom fields
      const [standardFieldsResponse, customFieldsResponse] = await Promise.all([
        api.get(`/api/available-fields/${fileType}`),
        api.get(`/api/custom-fields/file-type/${fileType}`)
      ]);

      const standardFields = standardFieldsResponse.data.fields || [];
      const customFields = customFieldsResponse.data.data || [];

      // Convert custom fields to the same format as standard fields
      const formattedCustomFields = customFields.map((field: any) => ({
        value: `custom_${field.field_name}`, // Prefix custom fields to avoid duplicates
        label: field.display_name,
        description: field.description || `Custom field: ${field.display_name}`,
        mandatory: field.is_mandatory === 1,
        important: field.is_important === 1,
        priority: field.is_mandatory ? 'mandatory' : (field.is_important ? 'important' : 'optional'),
        type: 'custom'
      }));

      // Combine standard and custom fields, ensuring no duplicates
      const standardFieldValues = new Set(standardFields.map((field: any) => field.value));
      const uniqueCustomFields = formattedCustomFields.filter((field: AvailableField) => 
        !standardFieldValues.has(field.value.replace('custom_', ''))
      );

      let allFields: AvailableField[] = [...standardFields, ...uniqueCustomFields];

      // Prune redundant fields for firewall mapping (unified service and protocol auto-detect)
      if (fileType === 'firewall') {
        const remove = new Set(['protocol', 'service_port', 'dest_port', 'service_name']);
        allFields = allFields.filter((f: any) => !remove.has((f as any).value));
        // Ensure unified Service field is present
        const hasService = allFields.some((f: any) => (f as any).value === 'service');
        if (!hasService) {
          allFields.unshift({
            value: 'service',
            label: 'Service (Name/Port)',
            description: 'Unified service field: name or numeric port or proto/port',
            mandatory: false,
            important: true,
            priority: 'important'
          } as any);
        }
      }

      setAvailableFields(allFields);
    } catch (error) {
      console.error('Error fetching available fields:', error);
    }
  };

  const handleMappingChange = (column: string, field: string) => {
    setMapping(prev => ({
      ...prev,
      [column]: Array.from(new Set([...(prev[column] || []), field]))
    }));
  };

  const handleAutoApply = () => {
    if (!detectionResult) return;

    const autoMapping: { [key: string]: string[] } = {};
    Object.entries(detectionResult.detected_fields).forEach(([column, field]) => {
      autoMapping[column] = [field];
    });

    setMapping(autoMapping);
    setAutoApplied(true);
  };

  const handleSave = () => {
    // Validate mandatory fields
    const mandatoryFields = availableFields.filter(field => field.mandatory);
    const mappedFields = new Set<string>();
    Object.values(mapping).forEach(arr => (arr || []).forEach(v => mappedFields.add(v)));
    const missingMandatory = mandatoryFields.filter(field => !mappedFields.has(field.value));
    
    if (missingMandatory.length > 0) {
      setValidationErrors(missingMandatory && missingMandatory.map(field => `${field.label} is mandatory and must be mapped`));
      return;
    }
    
    setValidationErrors([]);
    onSave(mapping);
    onClose();
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.5) return 'warning';
    return 'error';
  };

  const getConfidenceLabel = (confidence: number) => {
    if (confidence >= 0.8) return 'High';
    if (confidence >= 0.5) return 'Medium';
    return 'Low';
  };

  const renderSuggestions = (column: string, suggestions: FieldSuggestion[]) => {
    if (!suggestions || suggestions.length === 0) return null;

    return (
      <Box sx={{ mt: 1 }}>
        <Typography variant="caption" color="text.secondary">
          Suggestions:
        </Typography>
        {suggestions.slice(0, 3).map((suggestion, index) => (
          <Chip
            key={index}
            label={`${suggestion.field} (${Math.round(suggestion.confidence * 100)}%)`}
            size="small"
            variant="outlined"
            sx={{ ml: 0.5, mb: 0.5 }}
            onClick={() => handleMappingChange(column, suggestion.field)}
            clickable
          />
        ))}
      </Box>
    );
  };

  if (!file) return null;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h6">
            Smart Field Mapping - {file.name}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip
              label={fileType.toUpperCase()}
              color="primary"
              size="small"
            />
            {loading && <CircularProgress size={20} />}
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent>
        {loading ? (
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4 }}>
            <CircularProgress sx={{ mb: 2 }} />
            <Typography>Analyzing file and detecting fields...</Typography>
          </Box>
        ) : detectionResult?.error ? (
          <Alert severity="error" sx={{ mb: 2 }}>
            {detectionResult.error}
          </Alert>
        ) : detectionResult ? (
          <>
            {/* Validation errors */}
            {validationErrors.length > 0 && (
              <Alert severity="error" sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Please fix the following issues:
                </Typography>
                <ul style={{ margin: 0, paddingLeft: '20px' }}>
                  {validationErrors && validationErrors.map((error, index) => (
                    <li key={index}>{error}</li>
                  ))}
                </ul>
              </Alert>
            )}
            
            {/* Auto-detection summary */}
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="h6">
                    <AutoIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                    Automatic Field Detection
                  </Typography>
                  <Button
                    startIcon={<AutoIcon />}
                    onClick={handleAutoApply}
                    variant="outlined"
                    size="small"
                    disabled={!detectionResult.detected_fields || Object.keys(detectionResult.detected_fields).length === 0}
                  >
                    Auto-Apply All
                  </Button>
                </Box>
                
                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Detected Fields: {detectionResult.detected_fields ? Object.keys(detectionResult.detected_fields).length : 0}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Columns: {detectionResult.columns ? detectionResult.columns.length : 0}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      Total Rows: {detectionResult.total_rows || 0}
                    </Typography>
                  </Box>
                </Box>

                {/* Field Priority Status */}
                {detectionResult && detectionResult.mandatory_missing && detectionResult.mandatory_missing.length > 0 && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                      Missing Mandatory Fields:
                    </Typography>
                    <Box sx={{ mt: 1 }}>
                      {detectionResult.mandatory_missing.map((field, index) => (
                        <Chip
                          key={index}
                          label={field.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                          color="error"
                          size="small"
                          sx={{ mr: 1, mb: 1 }}
                        />
                      ))}
                    </Box>
                  </Alert>
                )}

                {detectionResult && detectionResult.important_missing && detectionResult.important_missing.length > 0 && (
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                      Missing Important Fields:
                    </Typography>
                    <Box sx={{ mt: 1 }}>
                      {detectionResult.important_missing.map((field, index) => (
                        <Chip
                          key={index}
                          label={field.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                          color="warning"
                          size="small"
                          sx={{ mr: 1, mb: 1 }}
                        />
                      ))}
                    </Box>
                  </Alert>
                )}

                {/* Column Mapping Table */}
                <TableContainer component={Paper} sx={{ mb: 2 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Column Name</TableCell>
                        <TableCell>Sample Data</TableCell>
                        <TableCell>Detected Field</TableCell>
                        <TableCell>Confidence</TableCell>
                        <TableCell>Priority</TableCell>
                        <TableCell>Manual Mapping</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {detectionResult && detectionResult.columns && detectionResult.columns.map((column) => {
                        const detectedField = detectionResult.detected_fields ? detectionResult.detected_fields[column] : null;
                        const confidence = detectionResult.confidence_scores ? (detectionResult.confidence_scores[column] || 0) : 0;
                        const suggestions = detectionResult.suggestions ? (detectionResult.suggestions[column] || []) : [];
                        const sampleData = detectionResult.preview_data && detectionResult.preview_data[0] ? (detectionResult.preview_data[0][column] || 'N/A') : 'N/A';

                        return (
                          <TableRow key={column}>
                            <TableCell>
                              <Typography variant="body2" fontWeight="bold">
                                {column}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {String(sampleData).substring(0, 50)}
                                {String(sampleData).length > 50 && '...'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              {detectedField ? (
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                                  <Chip
                                    label={detectedField}
                                    size="small"
                                    color={getConfidenceColor(confidence) as any}
                                  />
                                  <Tooltip title={`Confidence: ${Math.round(confidence * 100)}%`}>
                                    <Chip
                                      label={getConfidenceLabel(confidence)}
                                      size="small"
                                      variant="outlined"
                                    />
                                  </Tooltip>
                                  {detectionResult.field_priorities && detectionResult.field_priorities[column] && (
                                    <Chip
                                      label={detectionResult.field_priorities[column].toUpperCase()}
                                      size="small"
                                      color={
                                        detectionResult.field_priorities[column] === 'mandatory' ? 'error' :
                                        detectionResult.field_priorities[column] === 'important' ? 'warning' : 'default'
                                      }
                                      variant="outlined"
                                    />
                                  )}
                                </Box>
                              ) : (
                                <Typography variant="body2" color="text.secondary">
                                  No suggestion
                                </Typography>
                              )}
                              {renderSuggestions(column, suggestions)}
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {Math.round(confidence * 100)}%
                              </Typography>
                            </TableCell>
                            <TableCell>
                              {detectionResult.field_priorities && detectionResult.field_priorities[column] && (
                                <Chip
                                  label={detectionResult.field_priorities[column].toUpperCase()}
                                  size="small"
                                  color={
                                    detectionResult.field_priorities[column] === 'mandatory' ? 'error' :
                                    detectionResult.field_priorities[column] === 'important' ? 'warning' : 'default'
                                  }
                                  variant="outlined"
                                />
                              )}
                            </TableCell>
                            <TableCell>
                              <FormControl size="small" fullWidth>
                                <Select
                                  multiple
                                  value={mapping[column] || []}
                                  onChange={(e) => setMapping(prev => ({ ...prev, [column]: e.target.value as string[] }))}
                                  displayEmpty
                                  renderValue={(selected) => (selected as string[]).join(' ; ')}
                                >
                                  <MenuItem value="">
                                    <em>Skip this column</em>
                                  </MenuItem>
                                  {availableFields && availableFields.map((field) => (
                                    <MenuItem key={field.value} value={field.value}>
                                      <Tooltip title={field.description} placement="right">
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, justifyContent: 'space-between', width: '100%' }}>
                                          <span>{field.label}</span>
                                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                                            {field.mandatory && (
                                              <Chip label="REQ" size="small" color="error" variant="outlined" />
                                            )}
                                            {field.important && !field.mandatory && (
                                              <Chip label="IMP" size="small" color="warning" variant="outlined" />
                                            )}
                                          </Box>
                                        </Box>
                                      </Tooltip>
                                    </MenuItem>
                                  ))}
                                </Select>
                              </FormControl>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </TableContainer>

                {/* Data preview */}
                <Accordion expanded={showPreview} onChange={() => setShowPreview(!showPreview)}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">
                      <PreviewIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                      Data Preview ({detectionResult.preview_data ? detectionResult.preview_data.length : 0} rows shown)
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer component={Paper} sx={{ maxHeight: 300 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            {detectionResult.columns && detectionResult.columns.map((column) => (
                              <TableCell key={column}>
                                <Typography variant="body2" fontWeight="bold">
                                  {column}
                                </Typography>
                                {mapping[column] && (
                                  <Chip
                                    label={(mapping[column] || []).join(' ; ')}
                                    size="small"
                                    color="primary"
                                    variant="outlined"
                                    sx={{ mt: 0.5 }}
                                  />
                                )}
                              </TableCell>
                            ))}
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {detectionResult.preview_data && detectionResult.preview_data.slice(0, 10).map((row, index) => (
                            <TableRow key={index}>
                              {detectionResult.columns && detectionResult.columns.map((column) => (
                                <TableCell key={column}>
                                  <Typography variant="body2" sx={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {String(row[column] || '').substring(0, 30)}
                                    {String(row[column] || '').length > 30 && '...'}
                                  </Typography>
                                </TableCell>
                              ))}
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </AccordionDetails>
                </Accordion>

                {detectionResult.preview_data && detectionResult.preview_data.length > 0 && (
                  <Accordion sx={{ mt: 2 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">
                        <PreviewIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                        Mapped Output Preview (first 10 rows)
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      {(() => {
                        const targetFields = Array.from(new Set(Object.values(mapping).flat()));
                        if (targetFields.length === 0) {
                          return (
                            <Alert severity="info">No columns mapped yet. Select fields to see the output preview.</Alert>
                          );
                        }
                        return (
                          <TableContainer component={Paper} sx={{ maxHeight: 300 }}>
                            <Table size="small" stickyHeader>
                              <TableHead>
                                <TableRow>
                                  {targetFields.map((t) => (
                                    <TableCell key={t}>
                                      <Typography variant="body2" fontWeight="bold">
                                        {t}
                                      </Typography>
                                    </TableCell>
                                  ))}
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {detectionResult.preview_data.slice(0, 10).map((row, idx) => (
                                  <TableRow key={idx}>
                                    {targetFields.map((t) => {
                                      const sourceCols = Object.keys(mapping).filter((col) => (mapping[col] || []).includes(t));
                                      const values = sourceCols
                                        .map((col) => String(row[col] ?? '').trim())
                                        .filter((v) => v && v.toLowerCase() !== 'nan');
                                      const merged = values.join(' ; ');
                                      return (
                                        <TableCell key={t}>
                                          <Typography variant="body2" sx={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                            {merged}
                                          </Typography>
                                        </TableCell>
                                      );
                                    })}
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        );
                      })()}
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Mapping summary */}
                <Card sx={{ mt: 2 }}>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      Mapping Summary
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 2, mb: 1 }}>
                      <Chip
                        icon={<CheckIcon />}
                        label={`${Object.keys(mapping).length} columns mapped`}
                        color="success"
                        size="small"
                      />
                      <Chip
                        icon={<WarningIcon />}
                        label={`${(detectionResult.columns ? detectionResult.columns.length : 0) - Object.keys(mapping).length} columns skipped`}
                        color="warning"
                        size="small"
                      />
                    </Box>
                    {Object.keys(mapping).length === 0 && (
                      <Alert severity="warning" sx={{ mt: 1 }}>
                        No columns are currently mapped. The file will be uploaded but data may not be processed correctly.
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              </CardContent>
            </Card>
          </>
        ) : null}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={handleSave}
          variant="contained"
          disabled={loading}
          startIcon={loading ? <CircularProgress size={16} /> : undefined}
        >
          Save Mapping & Upload
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EnhancedColumnMappingDialog;
