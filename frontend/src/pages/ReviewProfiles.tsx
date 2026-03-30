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
  OutlinedInput
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Assignment as AssignmentIcon,
  Rule as RuleIcon,
  Link as LinkIcon,
  PlayArrow as PlayArrowIcon
} from '@mui/icons-material';

interface ReviewProfile {
  id: number;
  profile_name: string;
  description: string;
  compliance_framework: string;
  version: string;
  is_active: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  rules?: ProfileRuleLink[];
}

interface ProfileRuleLink {
  id: number;
  profile_id: number;
  rule_id: number;
  weight: number;
  is_mandatory: boolean;
  added_by: string;
  added_at: string;
  rule: ComplianceRule;
}

interface ComplianceRule {
  id: number;
  rule_name: string;
  description: string;
  field_to_check: string;
  operator: string;
  value: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  is_active: boolean;
}

const ReviewProfiles: React.FC = () => {
  const [profiles, setProfiles] = useState<ReviewProfile[]>([]);
  const [availableRules, setAvailableRules] = useState<ComplianceRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [totalCount, setTotalCount] = useState(0);
  
  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [openRulesDialog, setOpenRulesDialog] = useState(false);
  const [dialogMode, setDialogMode] = useState<'create' | 'edit' | 'view'>('create');
  const [selectedProfile, setSelectedProfile] = useState<ReviewProfile | null>(null);
  
  // Form state
  const [formData, setFormData] = useState({
    profile_name: '',
    description: '',
    compliance_framework: '',
    version: '',
    is_active: true,
    created_by: 'admin'
  });

  // Rule linking state
  const [selectedRules, setSelectedRules] = useState<{[key: number]: {weight: number, is_mandatory: boolean}}>({});
  
  // Run review state
  const [runningReview, setRunningReview] = useState<number | null>(null);

  useEffect(() => {
    fetchProfiles();
    fetchAvailableRules();
  }, [page, rowsPerPage]);

  const fetchProfiles = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        `http://localhost:5001/api/review-profiles?page=${page + 1}&per_page=${rowsPerPage}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch review profiles');
      }
      
      const data = await response.json();
      setProfiles(data.data || []);
      setTotalCount(data.pagination?.total || 0);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch review profiles');
    } finally {
      setLoading(false);
    }
  };

  const fetchAvailableRules = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/compliance-rules?per_page=100');
      if (!response.ok) throw new Error('Failed to fetch compliance rules');
      const data = await response.json();
      setAvailableRules(data.rules || []);
    } catch (err) {
      console.error('Error fetching compliance rules:', err);
    }
  };

  const fetchProfileDetails = async (profileId: number) => {
    try {
      const response = await fetch(`http://localhost:5001/api/review-profiles/${profileId}`);
      if (!response.ok) throw new Error('Failed to fetch profile details');
      const data = await response.json();
      return data;
    } catch (err) {
      console.error('Error fetching profile details:', err);
      return null;
    }
  };

  const handleCreateProfile = () => {
    setDialogMode('create');
    setSelectedProfile(null);
    setFormData({
      profile_name: '',
      description: '',
      compliance_framework: '',
      version: '',
      is_active: true,
      created_by: 'admin'
    });
    setOpenDialog(true);
  };

  const handleEditProfile = (profile: ReviewProfile) => {
    setDialogMode('edit');
    setSelectedProfile(profile);
    setFormData({
      profile_name: profile.profile_name,
      description: profile.description,
      compliance_framework: profile.compliance_framework,
      version: profile.version,
      is_active: profile.is_active,
      created_by: profile.created_by
    });
    setOpenDialog(true);
  };

  const handleViewProfile = (profile: ReviewProfile) => {
    setDialogMode('view');
    setSelectedProfile(profile);
    setFormData({
      profile_name: profile.profile_name,
      description: profile.description,
      compliance_framework: profile.compliance_framework,
      version: profile.version,
      is_active: profile.is_active,
      created_by: profile.created_by
    });
    setOpenDialog(true);
  };

  const handleManageRules = async (profile: ReviewProfile) => {
    setSelectedProfile(profile);
    
    // Fetch detailed profile info with rules
    const profileDetails = await fetchProfileDetails(profile.id);
    if (profileDetails) {
      const currentRules: {[key: number]: {weight: number, is_mandatory: boolean}} = {};
      profileDetails.rules?.forEach((link: ProfileRuleLink) => {
        currentRules[link.rule_id] = {
          weight: link.weight,
          is_mandatory: link.is_mandatory
        };
      });
      setSelectedRules(currentRules);
    }
    
    // Ensure latest list of available rules is loaded
    await fetchAvailableRules();
    
    setOpenRulesDialog(true);
  };

  const handleDeleteProfile = async (profileId: number) => {
    if (!window.confirm('Are you sure you want to delete this review profile?')) {
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/api/review-profiles/${profileId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete review profile');
      }

      setSuccess('Review profile deleted successfully');
      fetchProfiles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete review profile');
    }
  };

  const handleRunReview = async (profileId: number) => {
    if (!window.confirm('Are you sure you want to run a compliance review for this profile? This may take several minutes.')) {
      return;
    }

    setRunningReview(profileId);
    try {
      const response = await fetch(`http://localhost:5001/api/reviews/run/${profileId}`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to start review');
      }

      const data = await response.json();
      setSuccess(`Review started successfully! Session ID: ${data.data.review_session_id}`);
      
      // Optionally redirect to review results page
      setTimeout(() => {
        window.location.href = '/review-results';
      }, 2000);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start review');
    } finally {
      setRunningReview(null);
    }
  };

  const handleSubmit = async () => {
    try {
      const url = dialogMode === 'create' 
        ? 'http://localhost:5001/api/review-profiles'
        : `http://localhost:5001/api/review-profiles/${selectedProfile?.id}`;
      
      const method = dialogMode === 'create' ? 'POST' : 'PUT';
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        throw new Error(`Failed to ${dialogMode} review profile`);
      }

      setSuccess(`Review profile ${dialogMode === 'create' ? 'created' : 'updated'} successfully`);
      setOpenDialog(false);
      fetchProfiles();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${dialogMode} review profile`);
    }
  };

  const handleSaveRules = async () => {
    if (!selectedProfile) return;

    try {
      // Get current profile rules
      const profileDetails = await fetchProfileDetails(selectedProfile.id);
      const currentRuleIds = new Set<number>(profileDetails?.rules?.map((r: ProfileRuleLink) => r.rule_id) || []);
      const newRuleIds = new Set<number>(Object.keys(selectedRules).map(Number));

      // Remove rules that are no longer selected
      for (const ruleId of Array.from(currentRuleIds)) {
        if (!newRuleIds.has(ruleId)) {
          await fetch(`http://localhost:5001/api/review-profiles/${selectedProfile.id}/rules/${ruleId}`, {
            method: 'DELETE'
          });
        }
      }

      // Add new rules
      for (const [ruleId, config] of Object.entries(selectedRules)) {
        if (!currentRuleIds.has(Number(ruleId))) {
          await fetch(`http://localhost:5001/api/review-profiles/${selectedProfile.id}/rules`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              rule_id: Number(ruleId),
              weight: config.weight,
              is_mandatory: config.is_mandatory,
              added_by: 'admin'
            }),
          });
        }
      }

      setSuccess('Profile rules updated successfully');
      setOpenRulesDialog(false);
      fetchProfiles();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update profile rules');
    }
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleRuleToggle = (ruleId: number) => {
    setSelectedRules(prev => {
      const newSelected = { ...prev };
      if (newSelected[ruleId]) {
        delete newSelected[ruleId];
      } else {
        newSelected[ruleId] = { weight: 1.0, is_mandatory: false };
      }
      return newSelected;
    });
  };

  const handleRuleConfigChange = (ruleId: number, field: 'weight' | 'is_mandatory', value: any) => {
    setSelectedRules(prev => ({
      ...prev,
      [ruleId]: {
        ...prev[ruleId],
        [field]: value
      }
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

  const handleSeedDefaults = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:5001/api/review-profiles/seed-defaults', {
        method: 'POST'
      });
      if (!response.ok) throw new Error('Failed to seed default profiles');
      const result = await response.json();
      setSuccess(
        `Default profiles added: ${
          Array.isArray(result.profiles)
            ? result.profiles.map((p: any) => p.profile_name).join(', ')
            : 'PCI DSS, ISO 27001'
        }`
      );
      await fetchProfiles();
      await fetchAvailableRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to seed default profiles');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <AssignmentIcon sx={{ fontSize: 32, color: 'primary.main' }} />
          <Typography variant="h4" component="h1">
            Review Profiles
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<AddIcon />}
          onClick={handleSeedDefaults}
          sx={{ borderRadius: 2, mr: 1 }}
        >
          Add Default Profiles
        </Button>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleCreateProfile}
          sx={{ borderRadius: 2 }}
        >
          Create Profile
        </Button>
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
                <AssignmentIcon sx={{ color: 'primary.main' }} />
                <Box>
                  <Typography variant="h6">{totalCount}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Profiles
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
                <AssignmentIcon sx={{ color: 'success.main' }} />
                <Box>
                  <Typography variant="h6">
                    {profiles.filter(p => p.is_active).length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Active Profiles
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
                <RuleIcon sx={{ color: 'info.main' }} />
                <Box>
                  <Typography variant="h6">{availableRules.length}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Available Rules
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
                <LinkIcon sx={{ color: 'warning.main' }} />
                <Box>
                  <Typography variant="h6">
                    {profiles.reduce((sum, p) => sum + (p.rules?.length || 0), 0)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Links
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Box>

      {/* Profiles Table */}
      <Paper sx={{ borderRadius: 2 }}>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Profile Name</TableCell>
                <TableCell>Framework</TableCell>
                <TableCell>Version</TableCell>
                <TableCell>Rules Count</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Created By</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    Loading...
                  </TableCell>
                </TableRow>
              ) : profiles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    No review profiles found
                  </TableCell>
                </TableRow>
              ) : (
                profiles.map((profile) => (
                  <TableRow key={profile.id} hover>
                    <TableCell>
                      <Typography variant="subtitle2">{profile.profile_name}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {profile.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={profile.compliance_framework} 
                        size="small" 
                        color="primary"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>{profile.version}</TableCell>
                    <TableCell>
                      <Chip 
                        label={profile.rules?.length || 0} 
                        size="small" 
                        color="info"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={profile.is_active ? 'Active' : 'Inactive'} 
                        color={profile.is_active ? 'success' : 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{profile.created_by}</TableCell>
                    <TableCell align="center">
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="Run Review">
                          <IconButton 
                            size="small" 
                            color="success"
                            onClick={() => handleRunReview(profile.id)}
                            disabled={!profile.is_active || runningReview === profile.id}
                          >
                            <PlayArrowIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="View">
                          <IconButton 
                            size="small" 
                            onClick={() => handleViewProfile(profile)}
                          >
                            <ViewIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Edit">
                          <IconButton 
                            size="small" 
                            onClick={() => handleEditProfile(profile)}
                          >
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Manage Rules">
                          <IconButton 
                            size="small" 
                            color="info"
                            onClick={() => handleManageRules(profile)}
                          >
                            <LinkIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton 
                            size="small" 
                            color="error"
                            onClick={() => handleDeleteProfile(profile.id)}
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

      {/* Create/Edit Profile Dialog */}
      <Dialog 
        open={openDialog} 
        onClose={() => setOpenDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {dialogMode === 'create' ? 'Create Review Profile' : 
           dialogMode === 'edit' ? 'Edit Review Profile' : 'View Review Profile'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <Box sx={{ display: 'flex', gap: 2, flexDirection: { xs: 'column', sm: 'row' } }}>
                <Box sx={{ flex: 1 }}>
                  <TextField
                    fullWidth
                    label="Profile Name"
                    value={formData.profile_name}
                    onChange={(e) => setFormData({ ...formData, profile_name: e.target.value })}
                  />
                </Box>
                <Box sx={{ flex: 1 }}>
                  <TextField
                    fullWidth
                    label="Compliance Framework"
                    value={formData.compliance_framework}
                    onChange={(e) => setFormData({ ...formData, compliance_framework: e.target.value })}
                  />
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 2, flexDirection: { xs: 'column', sm: 'row' } }}>
                <Box sx={{ flex: 1 }}>
                  <TextField
                    fullWidth
                    label="Version"
                    value={formData.version}
                    onChange={(e) => setFormData({ ...formData, version: e.target.value })}
                  />
                </Box>
                <Box sx={{ flex: 1 }}>
                  <TextField
                    fullWidth
                    label="Created By"
                    value={formData.created_by}
                    onChange={(e) => setFormData({ ...formData, created_by: e.target.value })}
                  />
                </Box>
              </Box>
              <Box>
                <TextField
                  fullWidth
                  label="Description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </Box>
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

      {/* Manage Rules Dialog */}
      <Dialog 
        open={openRulesDialog} 
        onClose={() => setOpenRulesDialog(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          Manage Rules for {selectedProfile?.profile_name}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Select compliance rules to include in this profile. Configure weight and mandatory status for each rule.
            </Typography>
            
            {availableRules.length === 0 ? (
              <Box sx={{ p: 2, border: '1px dashed', borderColor: 'divider', borderRadius: 2, textAlign: 'center' }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  No rules available to select.
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Add default PCI DSS and ISO 27001 rules to get started.
                </Typography>
                <Button variant="outlined" startIcon={<AddIcon />} onClick={handleSeedDefaults}>
                  Add Default Rules
                </Button>
              </Box>
            ) : (
              <List>
                {availableRules.map((rule, index) => (
                  <React.Fragment key={rule.id}>
                    <ListItem>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={!!selectedRules[rule.id]}
                            onChange={() => handleRuleToggle(rule.id)}
                          />
                        }
                        label={
                          <Box>
                            <Typography variant="subtitle2">{rule.rule_name}</Typography>
                            <Typography variant="body2" color="text.secondary">
                              {rule.description}
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                              <Chip 
                                label={rule.severity} 
                                color={getSeverityColor(rule.severity) as any}
                                size="small"
                              />
                              <Chip 
                                label={`${rule.field_to_check} ${rule.operator}`} 
                                size="small" 
                                variant="outlined"
                              />
                            </Box>
                          </Box>
                        }
                      />
                      
                      {selectedRules[rule.id] && (
                        <ListItemSecondaryAction>
                          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                            <TextField
                              label="Weight"
                              type="number"
                              size="small"
                              sx={{ width: 80 }}
                              value={selectedRules[rule.id].weight}
                              onChange={(e) => handleRuleConfigChange(rule.id, 'weight', parseFloat(e.target.value))}
                              inputProps={{ min: 0.1, max: 10, step: 0.1 }}
                            />
                            <FormControlLabel
                              control={
                                <Checkbox
                                  checked={selectedRules[rule.id].is_mandatory}
                                  onChange={(e) => handleRuleConfigChange(rule.id, 'is_mandatory', e.target.checked)}
                                />
                              }
                              label="Mandatory"
                            />
                          </Box>
                        </ListItemSecondaryAction>
                      )}
                    </ListItem>
                    {index < availableRules.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenRulesDialog(false)}>
            Cancel
          </Button>
          <Button 
            onClick={handleSaveRules} 
            variant="contained"
          >
            Save Rules
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ReviewProfiles;
