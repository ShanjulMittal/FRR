import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Typography,
  Card,
  CardContent,
  Box,
  LinearProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import {
  Assessment as AssessmentIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { apiService } from '../services/api';

interface ReviewProfile {
  id: number;
  profile_name: string;
  compliance_framework: string;
  version: string;
}

interface RuleViolation {
  rule_id: number;
  rule_name: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  field_checked: string;
  operator: string;
  expected_value: string;
  field_value: string;
}

interface RuleEvaluationItem {
  normalized_rule_id: number;
  source_file: string;
  action: string;
  protocol: string;
  source_ip: string;
  dest_ip: string;
  service_port: string;
  evaluation: {
    profile_compliant: boolean;
    total_rules: number;
    passed_rules: number;
    failed_rules: number;
    compliance_score: number;
    violations: RuleViolation[];
  };
}

interface ComplianceRule {
  id: number;
  name: string;
  description: string;
  status: 'compliant' | 'warning' | 'violation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  affectedRules: number;
}

interface ComplianceMetrics {
  overallScore: number;
  totalRules: number;
  compliantRules: number;
  warningRules: number;
  violationRules: number;
}

const Compliance: React.FC = () => {
  const [metrics, setMetrics] = useState<ComplianceMetrics>({
    overallScore: 0,
    totalRules: 0,
    compliantRules: 0,
    warningRules: 0,
    violationRules: 0,
  });
  const [complianceRules, setComplianceRules] = useState<ComplianceRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'compliant' | 'warning' | 'violation'>('all');
  const [profiles, setProfiles] = useState<ReviewProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<number | null>(null);
  const [evaluationResults, setEvaluationResults] = useState<RuleEvaluationItem[]>([]);
  const [rulesMeta, setRulesMeta] = useState<Record<string, { description: string }>>({});

  useEffect(() => {
    const fetchComplianceData = async () => {
      try {
        setLoading(true);
        const data = await apiService.getComplianceMetrics();
        setMetrics(data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch compliance metrics');
        console.error('Error fetching compliance metrics:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchComplianceData();

    const fetchProfiles = async () => {
      try {
        const response = await fetch('http://localhost:5001/api/review-profiles?per_page=100');
        if (!response.ok) throw new Error('Failed to fetch profiles');
        const data = await response.json();
        const items = data.data || [];
        setProfiles(items);
        if (items.length > 0) {
          setSelectedProfile(items[0].id);
        }
      } catch (e) {
        console.error('Error fetching profiles:', e);
      }
    };

    const fetchRulesMeta = async () => {
      try {
        const response = await fetch('http://localhost:5001/api/compliance-rules?per_page=1000');
        if (!response.ok) throw new Error('Failed to fetch compliance rules');
        const data = await response.json();
        const map: Record<string, { description: string }> = {};
        (data.rules || []).forEach((r: any) => {
          map[r.rule_name] = { description: r.description };
        });
        setRulesMeta(map);
      } catch (e) {
        console.error('Error fetching compliance rules:', e);
      }
    };

    fetchProfiles();
    fetchRulesMeta();
  }, []);

  useEffect(() => {
    const fetchEvaluation = async () => {
      if (!selectedProfile) return;
      try {
        const response = await fetch(`http://localhost:5001/api/compliance/evaluate/profile/${selectedProfile}`);
        if (!response.ok) throw new Error('Failed to fetch evaluation results');
        const data = await response.json();
        const items: RuleEvaluationItem[] = data.rule_evaluations || [];
        setEvaluationResults(items);

        const totalRules = data.total_normalized_rules || items.length;
        let compliantCount = 0;
        let warningCount = 0;
        let violationCount = 0;

        items.forEach((item) => {
          const severities = item.evaluation.violations.map((v) => v.severity);
          const hasCriticalHigh = severities.some((s) => s === 'Critical' || s === 'High');
          const hasMediumLow = severities.some((s) => s === 'Medium' || s === 'Low');
          if (hasCriticalHigh) {
            violationCount += 1;
          } else if (hasMediumLow) {
            warningCount += 1;
          } else {
            compliantCount += 1;
          }
        });

        const overallScore = typeof data.overall_compliance_score === 'number'
          ? data.overall_compliance_score
          : (items.reduce((acc, it) => acc + (it.evaluation.compliance_score || 0), 0) / (items.length || 1));

        setMetrics({
          overallScore: Math.round((overallScore + Number.EPSILON) * 10) / 10,
          totalRules,
          compliantRules: compliantCount,
          warningRules: warningCount,
          violationRules: violationCount,
        });

        const affectedByRule: Record<string, Set<number>> = {};
        const severityByRule: Record<string, 'Critical' | 'High' | 'Medium' | 'Low'> = {};

        items.forEach((item) => {
          const seen: Set<string> = new Set();
          item.evaluation.violations.forEach((v) => {
            const rn = v.rule_name || 'Unknown';
            if (!affectedByRule[rn]) affectedByRule[rn] = new Set();
            if (!seen.has(rn)) {
              affectedByRule[rn].add(item.normalized_rule_id);
              seen.add(rn);
            }
            const current = severityByRule[rn];
            const order = ['Low', 'Medium', 'High', 'Critical'];
            if (!current || order.indexOf(v.severity) > order.indexOf(current)) {
              severityByRule[rn] = v.severity;
            }
          });
        });

        const list: ComplianceRule[] = Object.keys(affectedByRule).map((rn, idx) => {
          const sev = severityByRule[rn] || 'Medium';
          const status = sev === 'Critical' || sev === 'High' ? 'violation' : 'warning';
          const desc = rulesMeta[rn]?.description || '';
          const sevLower = sev.toLowerCase() as 'low' | 'medium' | 'high' | 'critical';
          return {
            id: idx + 1,
            name: rn,
            description: desc,
            status,
            severity: sevLower,
            affectedRules: affectedByRule[rn].size,
          };
        });
        setComplianceRules(list);
      } catch (e) {
        console.error('Error fetching evaluation:', e);
      }
    };
    fetchEvaluation();
  }, [selectedProfile, rulesMeta]);

  const displayedRules = statusFilter === 'all' 
    ? complianceRules 
    : complianceRules.filter((r) => r.status === statusFilter);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckIcon sx={{ color: 'success.main' }} />;
      case 'warning':
        return <WarningIcon sx={{ color: 'warning.main' }} />;
      case 'violation':
        return <ErrorIcon sx={{ color: 'error.main' }} />;
      default:
        return null;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'success';
      case 'warning':
        return 'warning';
      case 'violation':
        return 'error';
      default:
        return 'default';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low':
        return 'info';
      case 'medium':
        return 'warning';
      case 'high':
        return 'error';
      case 'critical':
        return 'error';
      default:
        return 'default';
    }
  };

  const navigate = useNavigate();

  const goToResults = (params: Record<string, string>) => {
    const query = new URLSearchParams(params).toString();
    navigate(`/review-results?${query}`);
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Compliance Dashboard
        </Typography>
        <FormControl sx={{ minWidth: 300 }}>
          <InputLabel>Select Review Profile</InputLabel>
          <Select
            value={selectedProfile ?? ''}
            onChange={(e: SelectChangeEvent<number | ''>) => setSelectedProfile(e.target.value as number)}
            label="Select Review Profile"
          >
            {profiles.map((profile) => (
              <MenuItem key={profile.id} value={profile.id}>
                {profile.profile_name} ({profile.compliance_framework})
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Compliance Score Overview */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" alignItems="center" mb={2}>
            <AssessmentIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6">Overall Compliance Score</Typography>
          </Box>
          {loading ? (
            <LinearProgress />
          ) : (
            <>
              <Typography variant="h3" color="primary" gutterBottom>
                {metrics.overallScore}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={metrics.overallScore}
                sx={{ height: 10, borderRadius: 5, mb: 2 }}
                color={metrics.overallScore >= 90 ? 'success' : metrics.overallScore >= 70 ? 'warning' : 'error'}
              />
              <Typography variant="body2" color="text.secondary">
                Based on {metrics.totalRules} total rules analyzed
              </Typography>
            </>
          )}
        </CardContent>
      </Card>

      {/* Compliance Metrics Cards */}
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 3 }}>
        <Card onClick={() => goToResults({ status: 'compliant' })} sx={{ cursor: 'pointer' }}>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="success.main">
              {metrics.compliantRules}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Compliant Rules
            </Typography>
          </CardContent>
        </Card>
        <Card onClick={() => goToResults({ status: 'non_compliant', category: 'warning' })} sx={{ cursor: 'pointer' }}>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="warning.main">
              {metrics.warningRules}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Warning Rules
            </Typography>
          </CardContent>
        </Card>
        <Card onClick={() => goToResults({ status: 'non_compliant', category: 'violation' })} sx={{ cursor: 'pointer' }}>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="error.main">
              {metrics.violationRules}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Violation Rules
            </Typography>
          </CardContent>
        </Card>
        <Card onClick={() => goToResults({})} sx={{ cursor: 'pointer' }}>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4">
              {metrics.totalRules}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Total Rules
            </Typography>
          </CardContent>
        </Card>
      </Box>

      {/* Compliance Alerts */}
      <Box sx={{ mb: 3 }}>
        <Alert severity="error" sx={{ mb: 1 }}>
          <strong>Critical:</strong> 23 overly permissive rules detected that allow unrestricted access
        </Alert>
        <Alert severity="warning">
          <strong>Warning:</strong> 15 access lists are missing explicit deny rules at the end
        </Alert>
      </Box>

      {/* Compliance Rules Table */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              Compliance Rules Analysis
            </Typography>
            <Button variant="outlined" startIcon={<DownloadIcon />} size="small">
              Export Report
            </Button>
          </Box>

          {statusFilter !== 'all' && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <Chip
                label={`Filtered: ${statusFilter.charAt(0).toUpperCase() + statusFilter.slice(1)} Rules`}
                color={statusFilter === 'compliant' ? 'success' : statusFilter === 'warning' ? 'warning' : 'error'}
                variant="outlined"
              />
              <Button size="small" onClick={() => setStatusFilter('all')}>Clear filter</Button>
            </Box>
          )}

          <TableContainer component={Paper} elevation={0}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Status</TableCell>
                  <TableCell>Rule Name</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Affected Rules</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {displayedRules.map((rule) => (
                  <TableRow
                    key={rule.id}
                    hover
                    onClick={() => {
                      const isCompliant = rule.status === 'compliant';
                      const params: Record<string, string> = {
                        rule_name: rule.name,
                        ...(isCompliant
                          ? { status: 'compliant' }
                          : { status: 'non_compliant', category: rule.status === 'warning' ? 'warning' : 'violation' })
                      };
                      goToResults(params);
                    }}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        {getStatusIcon(rule.status)}
                        <Chip label={rule.status} color={getStatusColor(rule.status) as any} size="small" sx={{ ml: 1 }} />
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {rule.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {rule.description}
                    </TableCell>
                    <TableCell>
                      <Chip label={rule.severity} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      {rule.affectedRules}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Container>
  );
};

export default Compliance;
