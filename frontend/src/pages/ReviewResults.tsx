import React, { useEffect, useState, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  TextField,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
  Tooltip,
  IconButton,
  TablePagination,
  Checkbox,
  FormControlLabel,
  List,
  ListItem,
  ListItemButton,
  ListItemText
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  PlayArrow as PlayArrowIcon,
  GetApp as GetAppIcon,
  PictureAsPdf as PictureAsPdfIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  ArrowForward as ArrowForwardIcon,
  ArrowBack as ArrowBackIcon,
  ArrowUpward as ArrowUpwardIcon,
  ArrowDownward as ArrowDownwardIcon,
  Delete as DeleteIcon
} from '@mui/icons-material';

interface ReviewSession {
  review_session_id: string;
  profile_id: number;
  profile_name: string;
  started_at: string;
  total_checks: number;
}

interface ReviewSummary {
  review_session_id: string;
  profile: {
    id: number;
    name: string;
    framework: string;
  };
  execution_time: string;
  statistics: {
    total_rules_scanned: number;
    total_checks_performed: number;
    compliant_count: number;
    non_compliant_count: number;
    compliance_percentage: number;
    findings_by_rule: { [key: string]: number };
    severity_breakdown: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
    };
  };
}

interface ReviewResult {
  id: number;
  status: string;
  severity: string;
  failed_checks: Array<{
    rule_name: string;
    field_checked: string;
    operator: string;
    expected_value: string;
    actual_value: string;
    description: string;
  }>;
  normalized_rule: {
    id: number;
    source_file: string;
    rule_name?: string;
    action: string;
    protocol: string;
    source_ip: string;
    dest_ip: string;
    service_name: string;
    raw_text?: string;
    rule_text?: string;
  };
  raw_rule?: { [key: string]: any } | null;
  compliance_rule: {
    id: number;
    rule_name: string;
    description: string;
    severity: string;
  };
  checked_at: string;
}

interface ReviewProfile {
  id: number;
  profile_name: string;
  description: string;
  compliance_framework: string;
}

const ReviewResults: React.FC = () => {
  const [sessions, setSessions] = useState<ReviewSession[]>([]);
  const [profiles, setProfiles] = useState<ReviewProfile[]>([]);
  const [selectedSession, setSelectedSession] = useState<string>('');
  const [summary, setSummary] = useState<ReviewSummary | null>(null);
  const [results, setResults] = useState<ReviewResult[]>([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(50);
  const [totalCount, setTotalCount] = useState(0);
  const [ruleSearchText, setRuleSearchText] = useState('');
  // Add URL-driven filtering helpers
  const location = useLocation();
  const navigate = useNavigate();
  const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const statusFilter = params.get('status');
  const categoryFilter = params.get('category');
  const severityFilter = params.get('severity');
  const ruleNameFilter = params.get('rule_name');
  const [displayedResults, setDisplayedResults] = useState<ReviewResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [runDialogOpen, setRunDialogOpen] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState<number | ''>('');
  const [runningReview, setRunningReview] = useState(false);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [selectedResult, setSelectedResult] = useState<ReviewResult | null>(null);
  // Normalized rule full-details dialog state
  const [viewRuleDialogOpen, setViewRuleDialogOpen] = useState(false);
  const [selectedNormalizedRule, setSelectedNormalizedRule] = useState<any | null>(null);
  // New: findings-by-rule dialog state
  const [findingsDialogOpen, setFindingsDialogOpen] = useState(false);
  const [selectedRuleName, setSelectedRuleName] = useState<string>('');
  const [ruleFindings, setRuleFindings] = useState<any[]>([]);
  // Add check-level findings state
  interface FailedCheck {
    rule_name: string;
    field_checked: string;
    operator: string;
    expected_value: string;
    actual_value: string;
    description: string;
  }
  interface RuleCheckFinding {
    result: ReviewResult;
    check: FailedCheck;
  }
  const [ruleCheckFindings, setRuleCheckFindings] = useState<RuleCheckFinding[]>([]);
  const [checkDialogOpen, setCheckDialogOpen] = useState(false);
  const [selectedComplianceRuleName, setSelectedComplianceRuleName] = useState<string>('');
  const [selectedComplianceResults, setSelectedComplianceResults] = useState<ReviewResult[]>([]);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [exportFormat, setExportFormat] = useState<'pdf'|'excel'|'csv'>('pdf');
  const [exportIncludeCompliant, setExportIncludeCompliant] = useState(false);
  const [exportGroupBy, setExportGroupBy] = useState<string>('');
  const [exportSourceFile, setExportSourceFile] = useState<string>('');
  const [exportProfiles, setExportProfiles] = useState<any[]>([]);
  const [selectedExportProfileId, setSelectedExportProfileId] = useState<number | ''>('');
  const [createExportProfileOpen, setCreateExportProfileOpen] = useState(false);
  const [creatingExportProfile, setCreatingExportProfile] = useState(false);
  const [availableExportFields, setAvailableExportFields] = useState<any[]>([]);
  const [newExportProfile, setNewExportProfile] = useState({
    profile_name: '',
    format: 'pdf' as 'pdf'|'excel'|'csv',
    include_compliant: true,
    group_by: '',
    selected_fields: [] as string[],
    include_sections: [] as string[],
    charts: { severity_chart: true, violations_chart: true }
  });
  const openCreateExportProfile = async () => {
    try {
      setCreateExportProfileOpen(true);
      const res = await fetch('http://localhost:5001/api/compliance/fields');
      const data = await res.json();
      const fields = (data.fields || []).map((f:any)=>({ name: f.name, description: f.description }));
      setAvailableExportFields(fields);
    } catch (e) {
      setAvailableExportFields([
        { name: 'Rule_Name', description: 'Rule name' },
        { name: 'action', description: 'Action' },
        { name: 'protocol', description: 'Protocol' },
        { name: 'source_zone', description: 'Source Zone' },
        { name: 'source_ip', description: 'Source IP' },
        { name: 'dest_zone', description: 'Destination Zone' },
        { name: 'dest_ip', description: 'Destination IP' },
        { name: 'service_port', description: 'Service Port' }
      ]);
    }
  };
  const submitCreateExportProfile = async () => {
    try {
      if (!newExportProfile.profile_name.trim()) {
        alert('Profile name is required');
        return;
      }
      setCreatingExportProfile(true);
      const body: any = {
        profile_name: newExportProfile.profile_name.trim(),
        format: newExportProfile.format,
        include_compliant: newExportProfile.include_compliant
      };
      if (newExportProfile.group_by) body.group_by = newExportProfile.group_by;
      body.selected_fields = newExportProfile.selected_fields;
      body.include_sections = newExportProfile.include_sections;
      body.charts = newExportProfile.charts;
      const res = await fetch('http://localhost:5001/api/export/profiles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || 'Failed to create export profile');
      }
      const data = await res.json();
      if (data && data.success) {
        const created = data.data;
        setExportProfiles(prev => [created, ...prev]);
        setSelectedExportProfileId(created.id);
        setCreateExportProfileOpen(false);
        setNewExportProfile({ profile_name: '', format: 'pdf', include_compliant: true, group_by: '', selected_fields: [], include_sections: [], charts: { severity_chart: true, violations_chart: true } });
      } else {
        alert('Failed to create export profile');
      }
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to create export profile');
    } finally {
      setCreatingExportProfile(false);
    }
  };
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteMode, setDeleteMode] = useState<'session'|'all'|'older'>('session');
  const [deleteOlderDays, setDeleteOlderDays] = useState<number>(30);

  const complianceOverview = useMemo(() => {
    const fromSummary = (summary?.statistics as any)?.checks_by_rule;
    if (fromSummary && typeof fromSummary === 'object') {
      const arr = Object.values(fromSummary as any).map((x: any) => ({
        name: x.name,
        severity: x.severity,
        description: x.description,
        compliant: Number(x.compliant || 0),
        nonCompliant: Number((x.non_compliant ?? x.nonCompliant) || 0),
        total: Number(x.total || 0)
      }));
      return arr.sort((a, b) => a.name.localeCompare(b.name));
    }
    const groups: Record<string, { name: string; severity: string; description: string; compliant: number; nonCompliant: number; total: number; }> = {};
    results.forEach((r) => {
      const key = r.compliance_rule?.rule_name || 'Unknown';
      if (!groups[key]) {
        groups[key] = {
          name: r.compliance_rule?.rule_name || 'Unknown',
          severity: r.compliance_rule?.severity || 'Medium',
          description: r.compliance_rule?.description || '',
          compliant: 0,
          nonCompliant: 0,
          total: 0,
        };
      }
      if (r.status === 'compliant') groups[key].compliant += 1; else groups[key].nonCompliant += 1;
      groups[key].total += 1;
    });
    return Object.values(groups).sort((a, b) => a.name.localeCompare(b.name));
  }, [summary, results]);

  const openComplianceRule = async (ruleName: string) => {
    setSelectedComplianceRuleName(ruleName);
    try {
      const qp = new URLSearchParams();
      if (selectedSession) qp.set('session_id', selectedSession);
      qp.set('rule_name', ruleName);
      const resp = await fetch(`http://localhost:5001/api/reviews/results?${qp.toString()}`);
      const data = await resp.json();
      const fetched: ReviewResult[] = resp.ok && data.success ? (data.data as ReviewResult[]) : [];
      setSelectedComplianceResults(fetched);
    } catch (e) {
      setSelectedComplianceResults([]);
    }
    setCheckDialogOpen(true);
  };

  useEffect(() => {
    fetchSessions();
    fetchProfiles();
  }, []);

  useEffect(() => {
    if (selectedSession) {
      fetchSummary(selectedSession);
      setResults([]);
      setPage(0);
      setTotalCount(0);
      setRuleSearchText(ruleNameFilter || '');
    }
  }, [selectedSession]);

  useEffect(() => {
    if (!selectedSession) return;
    const hasFilters = Boolean(statusFilter || categoryFilter || severityFilter || ruleNameFilter);
    if (hasFilters) {
      fetchResultsPage(true);
    }
  }, [selectedSession, statusFilter, categoryFilter, severityFilter, ruleNameFilter]);

  const fetchSessions = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/reviews/sessions');
      const data = await response.json();
      if (data.success) {
        setSessions(data.data);
        if (data.data.length > 0 && !selectedSession) {
          setSelectedSession(data.data[0].review_session_id);
        }
      }
    } catch (error) {
      console.error('Error fetching sessions:', error);
    }
  };

  const fetchProfiles = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/review-profiles');
      const data = await response.json();
      if (data.success) {
        setProfiles(data.data);
      }
    } catch (error) {
      console.error('Error fetching profiles:', error);
    }
  };

  const fetchSummary = async (sessionId: string) => {
    setLoading(true);
    try {
      const response = await fetch(`http://localhost:5001/api/reviews/summary/${sessionId}`);
      const data = await response.json();
      if (data.success) {
        setSummary(data.data);
      }
    } catch (error) {
      console.error('Error fetching summary:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchResultsPage = async (reset: boolean = false) => {
    try {
      if (!selectedSession) return;
      const limit = rowsPerPage;
      const currentPage = reset ? 0 : page;
      const offset = currentPage * limit;
      const qp = new URLSearchParams();
      qp.set('session_id', selectedSession);
      qp.set('limit', String(limit));
      qp.set('offset', String(offset));
      if (statusFilter) qp.set('status', statusFilter);
      if (ruleNameFilter) qp.set('rule_name', ruleNameFilter);
      const resp = await fetch(`http://localhost:5001/api/reviews/results?${qp.toString()}`);
      const data = await resp.json();
      if (!data.success) return;
      const batch: ReviewResult[] = data.data || [];
      const total: number = data.total_count || batch.length;
      setResults(batch);
      setTotalCount(total);
      if (reset) setPage(0);
    } catch (error) {
      console.error('Error fetching results:', error);
    }
  };

  useEffect(() => {
    // Apply URL param filters to results
    let filtered = results;
    if (statusFilter) {
      filtered = filtered.filter((r) => r.status === statusFilter);
    }
    if (categoryFilter === 'warning') {
      filtered = filtered.filter((r) => ['Low', 'Medium'].includes(r.severity));
    } else if (categoryFilter === 'violation') {
      filtered = filtered.filter((r) => ['High', 'Critical'].includes(r.severity));
    }
    if (severityFilter) {
      filtered = filtered.filter((r) => r.severity === severityFilter);
    }
    if (ruleNameFilter) {
      filtered = filtered.filter((r) => r.compliance_rule?.rule_name === ruleNameFilter);
    }
    setDisplayedResults(filtered);
  }, [results, statusFilter, categoryFilter, severityFilter, ruleNameFilter]);

  const clearFilters = () => navigate('/review-results');

  const setFilterParam = (key: string, value?: string) => {
    const newParams = new URLSearchParams(location.search);
    if (value === undefined) newParams.delete(key); else newParams.set(key, value);
    const qs = newParams.toString();
    navigate(qs ? `/review-results?${qs}` : '/review-results');
  };
  const setStatusFilterOnlyNonCompliant = () => setFilterParam('status', 'non_compliant');
  const clearStatusFilter = () => setFilterParam('status', undefined);

  const openNormalizedRuleDetails = async (ruleId: number) => {
    try {
      const resp = await fetch(`http://localhost:5001/api/normalized-rules/${ruleId}/details`);
      if (!resp.ok) {
        throw new Error('Failed to load normalized rule details');
      }
      const data = await resp.json();
      setSelectedNormalizedRule(data);
      setViewRuleDialogOpen(true);
    } catch (e) {
      console.error('Error fetching normalized rule details:', e);
      alert('Error loading full normalized rule details');
    }
  };

  const runReview = async () => {
    if (!selectedProfile) return;
    
    setRunningReview(true);
    try {
      const response = await fetch(`http://localhost:5001/api/reviews/run/${selectedProfile}`, {
        method: 'POST'
      });
      const data = await response.json();
      
      if (data.success) {
        setRunDialogOpen(false);
        setSelectedProfile('');
        // Refresh sessions and select the new one
        await fetchSessions();
        setSelectedSession(data.data.review_session_id);
      } else {
        alert(`Error running review: ${data.error}`);
      }
    } catch (error) {
      console.error('Error running review:', error);
      alert('Error running review');
    } finally {
      setRunningReview(false);
    }
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

  // New: open findings dialog for a specific compliance rule
  const openFindingsForRule = async (ruleName: string) => {
    setSelectedRuleName(ruleName);
    try {
      const qp = new URLSearchParams();
      if (selectedSession) qp.set('session_id', selectedSession);
      qp.set('rule_name', ruleName);
      qp.set('status', 'non_compliant');
      const resp = await fetch(`http://localhost:5001/api/reviews/results?${qp.toString()}`);
      const data = await resp.json();
      const fetched: ReviewResult[] = resp.ok && data.success ? (data.data as ReviewResult[]) : [];
      setRuleFindings(fetched);
      const checkFindings: RuleCheckFinding[] = fetched.flatMap((r) =>
        (r.failed_checks || [])
          .filter((fc) => fc.rule_name === ruleName)
          .map((fc) => ({ result: r, check: fc }))
      );
      setRuleCheckFindings(checkFindings);
    } catch (e) {
      setRuleFindings([]);
      setRuleCheckFindings([]);
    }
    setFindingsDialogOpen(true);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const handleExportExcel = async () => {
    if (!selectedSession) {
      alert('Please select a review session first');
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/api/export/excel/${selectedSession}`);
      
      if (!response.ok) {
        throw new Error('Export failed');
      }

      // Get the filename from the response headers
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = 'compliance_report.xlsx';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error exporting Excel:', error);
      alert('Error exporting to Excel');
    }
  };

  const handleExportCSV = async () => {
    if (!selectedSession) {
      alert('Please select a review session first');
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/api/export/csv/${selectedSession}`);
      
      if (!response.ok) {
        throw new Error('Export failed');
      }

      // Get the filename from the response headers
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = 'compliance_report.csv';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error exporting CSV:', error);
      alert('Error exporting to CSV');
    }
  };

  const handleExportPDF = async () => {
    if (!selectedSession) {
      alert('Please select a review session first');
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/api/export/pdf/${selectedSession}`);
      
      if (!response.ok) {
        throw new Error('Export failed');
      }

      // Get the filename from the response headers
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = 'compliance_report.pdf';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Create blob and download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error exporting PDF:', error);
      alert('Error exporting to PDF');
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Review Results
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<PlayArrowIcon />}
            onClick={() => setRunDialogOpen(true)}
          >
            Run New Review
          </Button>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchSessions}
          >
            Refresh
          </Button>
          <Button
            variant="outlined"
            startIcon={<VisibilityIcon />}
            onClick={() => fetchResultsPage(true)}
          >
            Load Results
          </Button>
          <TextField
            size="small"
            placeholder="Search rule name"
            value={ruleSearchText}
            onChange={(e) => setRuleSearchText(e.target.value)}
            onKeyDown={(e) => {
              if ((e as any).key === 'Enter') {
                setFilterParam('rule_name', ruleSearchText || undefined);
                fetchResultsPage(true);
              }
            }}
          />
          <Button
            variant="outlined"
            onClick={() => { setFilterParam('rule_name', ruleSearchText || undefined); fetchResultsPage(true); }}
          >
            Search
          </Button>
          <Button
            variant="outlined"
            onClick={() => setExportDialogOpen(true)}
          >
            Export...
          </Button>
          <Button
            variant="outlined"
            color="error"
            onClick={() => setDeleteDialogOpen(true)}
          >
            Delete Results...
          </Button>
          <Button
            variant="outlined"
            color="error"
            onClick={setStatusFilterOnlyNonCompliant}
          >
            Non-Compliant Only
          </Button>
          {statusFilter && (
            <Button variant="text" onClick={clearStatusFilter}>
              Show All
            </Button>
          )}
        </Box>
      </Box>

      {/* Session Selection */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Select Review Session
          </Typography>
          <FormControl fullWidth>
            <InputLabel>Review Session</InputLabel>
            <Select
              value={selectedSession}
              onChange={(e) => setSelectedSession(e.target.value)}
              label="Review Session"
            >
              {sessions.map((session) => (
                <MenuItem key={session.review_session_id} value={session.review_session_id}>
                  {session.profile_name} - {formatDate(session.started_at)} ({session.total_checks} checks)
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </CardContent>
      </Card>

      {loading && <LinearProgress sx={{ mb: 3 }} />}

      {summary && (
        <>
          {/* Dashboard Summary */}
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 3 }}>
            <Box sx={{ flex: '1 1 250px', minWidth: '250px' }}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Rules Scanned
                  </Typography>
                  <Typography variant="h4">
                    {summary.statistics.total_rules_scanned.toLocaleString()}
                  </Typography>
                </CardContent>
              </Card>
            </Box>
            <Box sx={{ flex: '1 1 250px', minWidth: '250px' }}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Non-Compliant
                  </Typography>
                  <Typography variant="h4" color="error">
                    {summary.statistics.non_compliant_count.toLocaleString()}
                  </Typography>
                </CardContent>
              </Card>
            </Box>
            <Box sx={{ flex: '1 1 250px', minWidth: '250px' }}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Compliance Score
                  </Typography>
                  <Typography variant="h4" color={summary.statistics.compliance_percentage >= 90 ? 'success.main' : 'warning.main'}>
                    {summary.statistics.compliance_percentage}%
                  </Typography>
                </CardContent>
              </Card>
            </Box>
            <Box sx={{ flex: '1 1 250px', minWidth: '250px' }}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Framework
                  </Typography>
                  <Typography variant="h6">
                    {summary.profile.framework || 'N/A'}
                  </Typography>
                </CardContent>
              </Card>
            </Box>
          </Box>

          {/* Severity Breakdown */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Findings by Severity
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                {Object.entries(summary.statistics.severity_breakdown).map(([severity, count]) => (
                  <Box key={severity} sx={{ flex: '1 1 200px', textAlign: 'center' }}>
                    <Chip
                      label={`${severity}: ${count}`}
                      color={getSeverityColor(severity) as any}
                      variant="outlined"
                      sx={{ mb: 1, cursor: 'pointer' }}
                      onClick={() => navigate(`/review-results?severity=${severity}`)}
                    />
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>

          {/* Findings by Compliance Rule */}
          <Box sx={{ mt: 4 }}>
            <Typography variant="h6" gutterBottom>
              Findings by Compliance Rule
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
              {Object.entries(summary.statistics.findings_by_rule || {}).map(([ruleName, count]) => (
                <Box
                  key={ruleName}
                  sx={{
                    flex: '1 1 300px',
                    p: 2,
                    border: '1px solid',
                    borderColor: 'grey.300',
                    borderRadius: 1
                  }}
                >
                  <Typography variant="subtitle1" sx={{ mb: 1 }}>
                    {ruleName}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <LinearProgress variant="determinate" value={Math.min(100, Number(count))} sx={{ flexGrow: 1 }} />
                    <Chip label={`${count}`} size="small" />
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Button size="small" variant="outlined" onClick={() => openFindingsForRule(ruleName)}>
                      View Findings
                    </Button>
                    <Button size="small" onClick={() => navigate(`/review-results?rule_name=${encodeURIComponent(ruleName)}`)}>
                      View in List
                    </Button>
                  </Box>
                </Box>
              ))}
            </Box>

          </Box>

          <Box sx={{ mt: 4 }}>
            <Typography variant="h6" gutterBottom>
              Compliance Checks Overview
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
              {complianceOverview.map((c) => (
                <Box key={c.name} sx={{ flex: '1 1 350px', p: 2, border: '1px solid', borderColor: 'grey.300', borderRadius: 1 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="subtitle1">{c.name}</Typography>
                    <Chip label={c.nonCompliant === 0 ? 'Compliant' : 'Issues'} color={c.nonCompliant === 0 ? 'success' : 'error'} size="small" />
                  </Box>
                  <Typography variant="caption" color="text.secondary">{c.description}</Typography>
                  <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
                    <Chip label={`Passed: ${c.compliant}`} color="success" variant="outlined" />
                    <Chip label={`Failed: ${c.nonCompliant}`} color="error" variant="outlined" />
                    <Chip label={`Total: ${c.total}`} variant="outlined" />
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Button size="small" variant="outlined" onClick={() => openComplianceRule(c.name)}>View Rules</Button>
                    <Button size="small" onClick={() => navigate(`/review-results?rule_name=${encodeURIComponent(c.name)}`)}>View in List</Button>
                  </Box>
                </Box>
              ))}
            </Box>
          </Box>
        </>
      )}

      {/* Active filter chips */}
      {(statusFilter || categoryFilter || severityFilter || ruleNameFilter) && (
        <Box sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}>
          {statusFilter && <Chip label={`Status: ${statusFilter}`} />}
          {categoryFilter && <Chip label={`Category: ${categoryFilter}`} />}
          {severityFilter && <Chip label={`Severity: ${severityFilter}`} />}
          {ruleNameFilter && <Chip label={`Rule: ${ruleNameFilter}`} />}
          <Button variant="text" onClick={clearFilters}>Clear filter</Button>
        </Box>
      )}

      {(statusFilter || categoryFilter || severityFilter || ruleNameFilter) && displayedResults.length === 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          No results matched the current filters. Try clearing filters.
        </Alert>
      )}

      {/* Detailed Results */}
      {displayedResults.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Rules ({displayedResults.length})
            </Typography>
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Source File</TableCell>
                    <TableCell>Rule Details</TableCell>
                    <TableCell>Compliance Rule</TableCell>
                    <TableCell>Compliance</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {displayedResults.map((result) => (
                    <TableRow key={result.id}>
                      <TableCell>{result.normalized_rule.source_file}</TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {result.normalized_rule.action} {result.normalized_rule.protocol}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {result.normalized_rule.source_ip} → {result.normalized_rule.dest_ip}
                        </Typography>
                      </TableCell>
                      <TableCell>{result.compliance_rule.rule_name}</TableCell>
                      <TableCell>
                        <Chip
                          label={result.status === 'compliant' ? 'Passed' : 'Failed'}
                          color={result.status === 'compliant' ? 'success' : 'error'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={result.severity}
                          color={getSeverityColor(result.severity) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => {
                              setSelectedResult(result);
                              setDetailsDialogOpen(true);
                            }}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                        <Button size="small" variant="text" onClick={() => openNormalizedRuleDetails(result.normalized_rule.id)} sx={{ ml: 1 }}>
                          View Rule
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              component="div"
              count={totalCount}
              page={page}
              onPageChange={(_, newPage) => { setPage(newPage); fetchResultsPage(false); }}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={(e) => { const v = parseInt((e.target as HTMLInputElement).value, 10); setRowsPerPage(v); setPage(0); fetchResultsPage(true); }}
            />
          </CardContent>
        </Card>
      )}

      {/* Run Review Dialog */}
      <Dialog open={runDialogOpen} onClose={() => setRunDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Run New Review</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Select Review Profile</InputLabel>
            <Select
              value={selectedProfile}
              onChange={(e) => setSelectedProfile(e.target.value as number)}
              label="Select Review Profile"
            >
              {profiles.map((profile) => (
                <MenuItem key={profile.id} value={profile.id}>
                  {profile.profile_name} ({profile.compliance_framework})
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRunDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={runReview}
            variant="contained"
            disabled={!selectedProfile || runningReview}
          >
            {runningReview ? <CircularProgress size={20} /> : 'Run Review'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Export Dialog */}
      <Dialog open={exportDialogOpen} onClose={() => setExportDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Export Review Report</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <FormControl fullWidth sx={{ gridColumn: '1 / span 2' }}>
              <InputLabel>Export Profile (optional)</InputLabel>
              <Select
                value={selectedExportProfileId}
                label="Export Profile (optional)"
                onOpen={async ()=>{
                  try {
                    const res = await fetch('http://localhost:5001/api/export/profiles');
                    const data = await res.json();
                    if (data && data.success) {
                      setExportProfiles(data.data || []);
                    }
                  } catch {}
                }}
                onChange={(e)=>setSelectedExportProfileId(e.target.value as number)}
              >
                <MenuItem value="">None</MenuItem>
                {exportProfiles.map((p:any)=> (
                  <MenuItem key={p.id} value={p.id}>{p.profile_name} ({p.format})</MenuItem>
                ))}
              </Select>
            </FormControl>
            <Box sx={{ gridColumn: '1 / span 2', display: 'flex', justifyContent: 'flex-end' }}>
              <Button size="small" onClick={openCreateExportProfile}>Create Export Profile</Button>
            </Box>
            <FormControl fullWidth>
              <InputLabel>Format</InputLabel>
              <Select value={exportFormat} label="Format" onChange={(e)=>setExportFormat(e.target.value as any)}>
                <MenuItem value="pdf">PDF</MenuItem>
                <MenuItem value="excel">Excel</MenuItem>
                <MenuItem value="csv">CSV</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>Group By</InputLabel>
              <Select value={exportGroupBy} label="Group By" onChange={(e)=>setExportGroupBy(e.target.value)}>
                <MenuItem value="">None</MenuItem>
                <MenuItem value="severity">Severity</MenuItem>
                <MenuItem value="rule">Compliance Rule</MenuItem>
                <MenuItem value="source_file">Source File</MenuItem>
              </Select>
            </FormControl>
            <TextField label="Source File (optional)" value={exportSourceFile} onChange={(e)=>setExportSourceFile(e.target.value)} />
            <Box sx={{ display:'flex', alignItems:'center' }}>
              <Chip label={exportIncludeCompliant ? 'Include Compliant' : 'Non-Compliant Only'} onClick={()=>setExportIncludeCompliant(!exportIncludeCompliant)} variant="outlined" />
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => {
            const sid = selectedSession;
            if (!sid) return;
            let url = '';
            const pid = selectedExportProfileId;
            if (exportFormat === 'pdf') {
              const qp = new URLSearchParams();
              if (pid) {
                if (exportSourceFile) qp.set('source_file', exportSourceFile);
                qp.set('profile_id', String(pid));
                url = `http://localhost:5001/api/export/pdf/custom/${sid}?${qp.toString()}`;
              } else {
                if (exportIncludeCompliant) qp.set('include_compliant','true');
                if (exportGroupBy) qp.set('group_by', exportGroupBy);
                if (exportSourceFile) qp.set('source_file', exportSourceFile);
                url = `http://localhost:5001/api/export/pdf/${sid}?${qp.toString()}`;
              }
            } else if (exportFormat === 'excel') {
              const qp = new URLSearchParams();
              if (pid) {
                qp.set('profile_id', String(pid));
                url = `http://localhost:5001/api/export/excel/custom/${sid}?${qp.toString()}`;
              } else {
                if (exportIncludeCompliant) qp.set('include_compliant','true');
                url = `http://localhost:5001/api/export/excel/${sid}?${qp.toString()}`;
              }
            } else {
              const qp = new URLSearchParams();
              if (pid) {
                if (exportSourceFile) qp.set('source_file', exportSourceFile);
                qp.set('profile_id', String(pid));
                url = `http://localhost:5001/api/export/csv/custom/${sid}?${qp.toString()}`;
              } else {
                if (exportSourceFile) qp.set('source_file', exportSourceFile);
                if (exportIncludeCompliant) qp.set('include_compliant','true');
                url = `http://localhost:5001/api/export/csv/${sid}?${qp.toString()}`;
              }
            }
            window.open(url, '_blank');
            setExportDialogOpen(false);
          }}>Download</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={createExportProfileOpen} onClose={()=>setCreateExportProfileOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Export Profile</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <TextField label="Profile Name" value={newExportProfile.profile_name} onChange={(e)=>setNewExportProfile({...newExportProfile, profile_name: e.target.value})} sx={{ gridColumn: '1 / span 2' }} />
            <FormControl fullWidth>
              <InputLabel>Format</InputLabel>
              <Select value={newExportProfile.format} label="Format" onChange={(e)=>setNewExportProfile({...newExportProfile, format: e.target.value as any, include_sections: e.target.value === 'pdf' ? newExportProfile.include_sections : [], charts: e.target.value === 'pdf' ? newExportProfile.charts : { severity_chart: false, violations_chart: false }})}>
                <MenuItem value="pdf">PDF</MenuItem>
                <MenuItem value="excel">Excel</MenuItem>
                <MenuItem value="csv">CSV</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>Group By</InputLabel>
              <Select value={newExportProfile.group_by} label="Group By" onChange={(e)=>setNewExportProfile({...newExportProfile, group_by: e.target.value})}>
                <MenuItem value="">None</MenuItem>
                <MenuItem value="severity">Severity</MenuItem>
                <MenuItem value="rule">Compliance Rule</MenuItem>
                <MenuItem value="source_file">Source File</MenuItem>
              </Select>
            </FormControl>
            <Box sx={{ display:'flex', alignItems:'center' }}>
              <Chip label={newExportProfile.include_compliant ? 'Include Compliant' : 'Non-Compliant Only'} onClick={()=>setNewExportProfile({...newExportProfile, include_compliant: !newExportProfile.include_compliant})} variant="outlined" />
            </Box>
            <Box sx={{ gridColumn: '1 / span 2', display: 'grid', gridTemplateColumns: '1fr 80px 1fr', gap: 2 }}>
              <Paper variant="outlined" sx={{ p: 1 }}>
                <Typography variant="subtitle2">Available Fields</Typography>
                <List dense>
                  {availableExportFields.filter((f:any)=>!newExportProfile.selected_fields.includes(f.name)).map((f:any)=> (
                    <ListItem key={f.name}>
                      <ListItemButton onClick={()=>setNewExportProfile({...newExportProfile, selected_fields: [...newExportProfile.selected_fields, f.name]})}>
                        <ListItemText primary={f.name} secondary={f.description} />
                      </ListItemButton>
                    </ListItem>
                  ))}
                </List>
              </Paper>
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                <IconButton onClick={()=>{
                  const remaining = availableExportFields.filter((f:any)=>!newExportProfile.selected_fields.includes(f.name)).map((f:any)=>f.name);
                  setNewExportProfile({...newExportProfile, selected_fields: [...newExportProfile.selected_fields, ...remaining]});
                }}><ArrowForwardIcon /></IconButton>
                <IconButton onClick={()=>setNewExportProfile({...newExportProfile, selected_fields: []})}><ArrowBackIcon /></IconButton>
              </Box>
              <Paper variant="outlined" sx={{ p: 1 }}>
                <Typography variant="subtitle2">Selected Fields</Typography>
                <List dense>
                  {newExportProfile.selected_fields.map((name, idx)=> (
                    <ListItem key={name} secondaryAction={
                      <Box>
                        <IconButton size="small" onClick={()=>{
                          if (idx>0) {
                            const arr = [...newExportProfile.selected_fields];
                            [arr[idx-1], arr[idx]] = [arr[idx], arr[idx-1]];
                            setNewExportProfile({...newExportProfile, selected_fields: arr});
                          }
                        }}><ArrowUpwardIcon fontSize="small" /></IconButton>
                        <IconButton size="small" onClick={()=>{
                          if (idx<newExportProfile.selected_fields.length-1) {
                            const arr = [...newExportProfile.selected_fields];
                            [arr[idx+1], arr[idx]] = [arr[idx], arr[idx+1]];
                            setNewExportProfile({...newExportProfile, selected_fields: arr});
                          }
                        }}><ArrowDownwardIcon fontSize="small" /></IconButton>
                        <IconButton size="small" onClick={()=>{
                          setNewExportProfile({...newExportProfile, selected_fields: newExportProfile.selected_fields.filter(n=>n!==name)});
                        }}><DeleteIcon fontSize="small" /></IconButton>
                      </Box>
                    }>
                      <ListItemText primary={name} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
            {newExportProfile.format === 'pdf' && (
              <Box sx={{ gridColumn: '1 / span 2' }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>PDF Sections</Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {['summary','charts','details','appendices'].map((sec)=> (
                    <Chip key={sec} label={sec} color={newExportProfile.include_sections.includes(sec) ? 'primary' : 'default'} variant="outlined" onClick={()=>{
                      const has = newExportProfile.include_sections.includes(sec);
                      setNewExportProfile({...newExportProfile, include_sections: has ? newExportProfile.include_sections.filter(s=>s!==sec) : [...newExportProfile.include_sections, sec]});
                    }} />
                  ))}
                </Box>
                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Charts</Typography>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <FormControlLabel control={<Checkbox checked={!!newExportProfile.charts.severity_chart} onChange={(e:any)=>setNewExportProfile({...newExportProfile, charts: {...newExportProfile.charts, severity_chart: e.target.checked}})} />} label="Severity Chart" />
                  <FormControlLabel control={<Checkbox checked={!!newExportProfile.charts.violations_chart} onChange={(e:any)=>setNewExportProfile({...newExportProfile, charts: {...newExportProfile.charts, violations_chart: e.target.checked}})} />} label="Violations Chart" />
                </Box>
              </Box>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={()=>setCreateExportProfileOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={submitCreateExportProfile} disabled={creatingExportProfile}>{creatingExportProfile ? <CircularProgress size={20} /> : 'Create'}</Button>
        </DialogActions>
      </Dialog>

      {/* Delete Results Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Delete Review Results</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Mode</InputLabel>
            <Select value={deleteMode} label="Mode" onChange={(e)=>setDeleteMode(e.target.value as any)}>
              <MenuItem value="session">Selected Session</MenuItem>
              <MenuItem value="older">Older Than N Days</MenuItem>
              <MenuItem value="all">Delete All</MenuItem>
            </Select>
          </FormControl>
          {deleteMode === 'session' && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              This will delete all results in session: {selectedSession || 'none selected'}
            </Alert>
          )}
          {deleteMode === 'older' && (
            <Box sx={{ mt: 2 }}>
              <TextField
                type="number"
                label="Older Than (days)"
                value={deleteOlderDays}
                onChange={(e)=>setDeleteOlderDays(parseInt(e.target.value || '0', 10))}
                fullWidth
              />
            </Box>
          )}
          {deleteMode === 'all' && (
            <Alert severity="error" sx={{ mt: 2 }}>
              This will delete ALL review results. This action cannot be undone.
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={async () => {
              try {
                let body: any = {};
                if (deleteMode === 'all') body.delete_all = true;
                else if (deleteMode === 'session') body.session_id = selectedSession;
                else if (deleteMode === 'older') body.older_than_days = deleteOlderDays;
                const resp = await fetch('http://localhost:5001/api/reviews/results/bulk-delete', {
                  method: 'DELETE',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(body)
                });
                const data = await resp.json();
                if (!resp.ok) {
                  alert(data.error || 'Failed to delete results');
                  return;
                }
                setDeleteDialogOpen(false);
                await fetchSessions();
                if (selectedSession) {
                  await fetchSummary(selectedSession);
                  await fetchResultsPage(true);
                }
              } catch (e) {
                alert('Error deleting results');
              }
            }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Findings By Rule Dialog */}
      <Dialog open={findingsDialogOpen} onClose={() => setFindingsDialogOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          Findings for: {selectedRuleName}
        </DialogTitle>
        <DialogContent>
          {ruleFindings.length === 0 ? (
            <Alert severity="info">No non-compliant findings for this rule in the selected session.</Alert>
          ) : (
            <TableContainer component={Paper} elevation={0}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>Compliance</TableCell>
                    <TableCell>Source File</TableCell>
                    <TableCell>Rule Name</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Protocol</TableCell>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Destination IP</TableCell>
                    <TableCell>Service</TableCell>
                    <TableCell>Raw Rule Text</TableCell>
                    <TableCell>Checked At</TableCell>
                    <TableCell align="center">Details</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {ruleFindings.map((res) => (
                    <TableRow key={res.id} hover>
                      <TableCell>
                        <Chip label={res.severity} color={getSeverityColor(res.severity) as any} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={res.status === 'compliant' ? 'Passed' : 'Failed'} color={res.status === 'compliant' ? 'success' : 'error'} size="small" />
                      </TableCell>
                      <TableCell>{res.normalized_rule?.source_file}</TableCell>
                      <TableCell>{res.normalized_rule?.rule_name}</TableCell>
                      <TableCell>{res.normalized_rule?.action}</TableCell>
                      <TableCell>{res.normalized_rule?.protocol}</TableCell>
                      <TableCell>{res.normalized_rule?.source_ip}</TableCell>
                      <TableCell>{res.normalized_rule?.dest_ip}</TableCell>
                      <TableCell>{res.normalized_rule?.service_name}</TableCell>
                      <TableCell style={{ whiteSpace: 'normal' }}>{res.normalized_rule?.raw_text}</TableCell>
                      <TableCell>{formatDate(res.checked_at)}</TableCell>
                      <TableCell align="center">
                        <Tooltip title="View full result">
                          <IconButton size="small" onClick={() => { setSelectedResult(res); setDetailsDialogOpen(true); }}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                        <Button size="small" variant="text" onClick={() => openNormalizedRuleDetails(res.normalized_rule?.id)} sx={{ ml: 1 }}>
                          View Rule
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFindingsDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={checkDialogOpen} onClose={() => setCheckDialogOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Compliance Check: {selectedComplianceRuleName}</DialogTitle>
        <DialogContent>
          {selectedComplianceResults.length === 0 ? (
            <Alert severity="info">No results for this compliance check in the selected session.</Alert>
          ) : (
            <TableContainer component={Paper} elevation={0}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Status</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Source File</TableCell>
                    <TableCell>Rule Name</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Protocol</TableCell>
                    <TableCell>Source IP</TableCell>
                    <TableCell>Destination IP</TableCell>
                    <TableCell>Service</TableCell>
                    <TableCell>Checked At</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {selectedComplianceResults.map((res) => (
                    <TableRow key={res.id} hover>
                      <TableCell>
                        <Chip label={res.status === 'compliant' ? 'Passed' : 'Failed'} color={res.status === 'compliant' ? 'success' : 'error'} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip label={res.severity} color={getSeverityColor(res.severity) as any} size="small" />
                      </TableCell>
                      <TableCell>{res.normalized_rule?.source_file}</TableCell>
                      <TableCell>{res.normalized_rule?.rule_name}</TableCell>
                      <TableCell>{res.normalized_rule?.action}</TableCell>
                      <TableCell>{res.normalized_rule?.protocol}</TableCell>
                      <TableCell>{res.normalized_rule?.source_ip}</TableCell>
                      <TableCell>{res.normalized_rule?.dest_ip}</TableCell>
                      <TableCell>{res.normalized_rule?.service_name}</TableCell>
                      <TableCell>{formatDate(res.checked_at)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCheckDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Details Dialog */}
      <Dialog open={detailsDialogOpen} onClose={() => setDetailsDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Rule Details</DialogTitle>
        <DialogContent>
          {selectedResult && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="h6" gutterBottom>
                Normalized Rule
              </Typography>
              <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                <Typography><strong>Rule Name:</strong> {selectedResult.normalized_rule.rule_name || 'N/A'}</Typography>
                <Typography><strong>Compliance Status:</strong> {selectedResult.status === 'compliant' ? 'Passed' : 'Failed'}</Typography>
                <Typography><strong>Action:</strong> {selectedResult.normalized_rule.action}</Typography>
                <Typography><strong>Protocol:</strong> {selectedResult.normalized_rule.protocol}</Typography>
                <Typography><strong>Source:</strong> {selectedResult.normalized_rule.source_ip}</Typography>
                <Typography><strong>Destination:</strong> {selectedResult.normalized_rule.dest_ip}</Typography>
                <Typography><strong>Service:</strong> {selectedResult.normalized_rule.service_name}</Typography>
                <Typography><strong>Raw Rule Text:</strong> {selectedResult.normalized_rule.raw_text}</Typography>
              </Box>

              <Typography variant="h6" gutterBottom>
                Uploaded File Fields (column → value)
              </Typography>
              <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                {selectedResult.raw_rule ? (
                  Object.entries(selectedResult.raw_rule).map(([key, value]) => (
                    <Typography key={key} sx={{ wordBreak: 'break-word' }}>
                      <strong>{key}:</strong> {value === null || value === undefined || value === '' ? 'N/A' : String(value)}
                    </Typography>
                  ))
                ) : (
                  <Alert severity="info">No raw rule payload available for this result.</Alert>
                )}
              </Box>

              <Typography variant="h6" gutterBottom>
                Compliance Rule
              </Typography>
              <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                <Typography><strong>Name:</strong> {selectedResult.compliance_rule.rule_name}</Typography>
                <Typography><strong>Severity:</strong> {selectedResult.compliance_rule.severity}</Typography>
                <Typography><strong>Description:</strong> {selectedResult.compliance_rule.description}</Typography>
              </Box>

              <Typography variant="h6" gutterBottom>
                Failed Compliance Checks
              </Typography>
              {selectedResult.failed_checks.map((check, index) => (
                <Accordion key={index}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>{check.rule_name}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography><strong>Description:</strong> {check.description}</Typography>
                    <Typography><strong>Field Checked:</strong> {check.field_checked}</Typography>
                    <Typography><strong>Operator:</strong> {check.operator}</Typography>
                    <Typography><strong>Expected:</strong> {check.expected_value}</Typography>
                    <Typography><strong>Actual:</strong> {check.actual_value}</Typography>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Normalized Rule Full Details Dialog */}
      <Dialog open={viewRuleDialogOpen} onClose={() => setViewRuleDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Normalized Rule Details</DialogTitle>
        <DialogContent>
          {selectedNormalizedRule && (
            <Box sx={{ mt: 1 }}>
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">ID</Typography>
                  <Typography>{selectedNormalizedRule.id}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Source File</Typography>
                  <Typography>{selectedNormalizedRule.source_file}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Action</Typography>
                  <Chip label={selectedNormalizedRule.action || 'N/A'} size="small" />
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Protocol</Typography>
                  <Chip label={selectedNormalizedRule.protocol || 'N/A'} size="small" />
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Source IP</Typography>
                  <Typography sx={{ overflowWrap: 'anywhere' }}>{selectedNormalizedRule.source_ip || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Destination IP</Typography>
                  <Typography sx={{ overflowWrap: 'anywhere' }}>{selectedNormalizedRule.dest_ip || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Destination Port</Typography>
                  <Typography sx={{ overflowWrap: 'anywhere' }}>{selectedNormalizedRule.dest_port || selectedNormalizedRule.service_port || 'N/A'}</Typography>
                </Box>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Service Name</Typography>
                  <Typography>{selectedNormalizedRule.service_name || 'N/A'}</Typography>
                </Box>
              </Box>
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">Raw Rule Text</Typography>
                <Typography sx={{ overflowWrap: 'anywhere' }}>{selectedNormalizedRule.raw_text || selectedNormalizedRule.rule_text || 'N/A'}</Typography>
              </Box>
              {selectedNormalizedRule.custom_fields_data && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="h6">Custom Fields</Typography>
                  {(() => {
                    try {
                      const cf = typeof selectedNormalizedRule.custom_fields_data === 'string' ? JSON.parse(selectedNormalizedRule.custom_fields_data) : selectedNormalizedRule.custom_fields_data;
                      const entries = Object.entries(cf || {});
                      if (entries.length === 0) return <Alert severity="info">No custom fields</Alert>;
                      return (
                        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                          {entries.map(([k, v]) => (
                            <Box key={k}>
                              <Typography variant="subtitle2" color="text.secondary">{k}</Typography>
                              <Typography>{String(v)}</Typography>
                            </Box>
                          ))}
                        </Box>
                      );
                    } catch (e) {
                      return <Alert severity="warning">Failed to parse custom fields</Alert>;
                    }
                  })()}
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewRuleDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {sessions.length === 0 && !loading && (
        <Alert severity="info">
          No review sessions found. Click "Run New Review" to start your first compliance review.
        </Alert>
      )}
    </Box>
  );
};

export default ReviewResults;
