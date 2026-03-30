import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Typography,
  Chip,
  Alert,
  LinearProgress,
  SelectChangeEvent,
  CircularProgress,
  Skeleton
} from '@mui/material';
import { Pagination } from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon
} from '@mui/icons-material';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  AreaChart,
  Area,
  Legend,
  BarChart,
  Bar
} from 'recharts';
import { useSearchParams } from 'react-router-dom';

interface ReviewProfile {
  id: number;
  profile_name: string;
  compliance_framework: string;
  version: string;
}

interface ComplianceDashboardData {
  summary: {
    total_rules: number;
    compliant_rules: number;
    non_compliant_rules: number;
    compliance_percentage: number;
  };
  violations_by_severity: {
    [key: string]: number;
  };
  top_violations: Array<{
    rule_id: number;
    rule_name: string;
    violation_count: number;
    severity: string;
  }>;
  compliance_trends: Array<{
    date: string;
    compliance_percentage: number;
  }>;
  metric_trends?: Array<{
    date: string;
    total_rules: number;
    compliant_rules: number;
    non_compliant_rules: number;
    compliance_percentage: number;
  }>;
  severity_over_time?: Array<{
    date: string;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  }>;
  sessions?: Array<{
    review_session_id: string;
    checked_at: string | null;
  }>;
  severity_compare_grouped?: Array<{
    date: string;
    Critical_A: number;
    High_A: number;
    Medium_A: number;
    Low_A: number;
    Critical_B: number;
    High_B: number;
    Medium_B: number;
    Low_B: number;
  }>;
  rule_summary?: Array<{
    rule_id: number;
    rule_name: string | null;
    severity: string | null;
    compliant_count: number;
    non_compliant_count: number;
  }>;
}

interface RuleViolation {
  rule_id: number;
  rule_name: string;
  severity: string;
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

const ComplianceDashboard: React.FC = () => {
  const [profiles, setProfiles] = useState<ReviewProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<number | ''>('');
  const [dashboardData, setDashboardData] = useState<ComplianceDashboardData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<'7' | '30' | '90' | 'all'>('30');
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(['Critical', 'High', 'Medium', 'Low']);
  const [compareMode, setCompareMode] = useState<boolean>(false);
  const [selectedProfileB, setSelectedProfileB] = useState<number | ''>('');
  const [dashboardDataB, setDashboardDataB] = useState<ComplianceDashboardData | null>(null);
  const [showLineA, setShowLineA] = useState<boolean>(true);
  const [showLineB, setShowLineB] = useState<boolean>(true);
  const [examplesOpen, setExamplesOpen] = useState<boolean>(false);
  const [examplesLoading, setExamplesLoading] = useState<boolean>(false);
  const [selectedViolationRuleId, setSelectedViolationRuleId] = useState<number | null>(null);
  const [violationExamples, setViolationExamples] = useState<any[]>([]);
  const [searchParams, setSearchParams] = useSearchParams();
  const [bucket, setBucket] = useState<'day' | 'week' | 'month'>('day');
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [ruleOnlyViolations, setRuleOnlyViolations] = useState<boolean>(false);
  const [ruleSort, setRuleSort] = useState<'non_compliant_count' | 'severity' | 'rule_name'>('non_compliant_count');
  const [ruleSortOrder, setRuleSortOrder] = useState<'asc' | 'desc'>('desc');
  const [rulePage, setRulePage] = useState<number>(1);
  const [ruleRowsPerPage, setRuleRowsPerPage] = useState<number>(10);

  useEffect(() => {
    fetchProfiles();
  }, []);

  useEffect(() => {
    if (selectedProfile) {
      fetchDashboardData();
    }
  }, [selectedProfile]);

  useEffect(() => {
    const initialRange = searchParams.get('range') as '7' | '30' | '90' | 'all' | null;
    const initialProfile = searchParams.get('profile_id');
    const initialSev = searchParams.get('sev');
    const initialBucket = searchParams.get('bucket') as 'day' | 'week' | 'month' | null;
    const initialSession = searchParams.get('session_id');
    if (initialRange && ['7','30','90','all'].includes(initialRange)) {
      setTimeRange(initialRange);
    }
    if (initialProfile) {
      const id = parseInt(initialProfile, 10);
      if (!Number.isNaN(id)) setSelectedProfile(id);
    }
    if (initialSev) {
      const parts = initialSev.split(',').filter(Boolean);
      if (parts.length > 0) setSelectedSeverities(parts);
    }
    if (initialBucket && ['day','week','month'].includes(initialBucket)) {
      setBucket(initialBucket);
    }
    if (initialSession) {
      setSelectedSessionId(initialSession);
    }
  }, []);

  useEffect(() => {
    const params: Record<string,string> = { range: timeRange, sev: selectedSeverities.join(','), bucket };
    if (selectedSessionId) params['session_id'] = selectedSessionId;
    if (selectedProfile) params['profile_id'] = String(selectedProfile);
    setSearchParams(params as any, { replace: true } as any);
  }, [timeRange, selectedSeverities, bucket, selectedSessionId]);

  useEffect(() => {
    const sp = searchParams.get('profile_id');
    const id = sp ? parseInt(sp, 10) : NaN;
    if (!Number.isNaN(id) && id !== selectedProfile) {
      setSelectedProfile(id);
    }
  }, [searchParams]);

  useEffect(() => {
    if (compareMode && selectedProfileB) {
      fetchDashboardData(true);
    }
  }, [compareMode, selectedProfileB]);

  const fetchProfiles = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/review-profiles?per_page=100');
      if (!response.ok) throw new Error('Failed to fetch profiles');
      const data = await response.json();
      setProfiles(data.data || []);
      
      // Auto-select first profile if available
      if (data.data && data.data.length > 0) {
        setSelectedProfile(data.data[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch profiles');
    }
  };

  const fetchDashboardData = async (forB: boolean = false) => {
    if (!selectedProfile) return;
    
    try {
      setLoading(true);
      const profileId = forB ? selectedProfileB : selectedProfile;
      const paramsObj: Record<string,string> = { range: timeRange, bucket };
      if (compareMode && selectedProfileB) paramsObj['profile_id_b'] = String(selectedProfileB);
      const qs = new URLSearchParams(paramsObj).toString();
      const response = await fetch(`http://localhost:5001/api/compliance/dashboard/profile/${profileId}?${qs}`);
      if (!response.ok) throw new Error('Failed to fetch dashboard data');
      const data = await response.json();
      setDashboardData(data);
      if (data.metric_trends_b || data.severity_over_time_b) {
        setDashboardDataB({
          summary: data.summary,
          violations_by_severity: data.violations_by_severity,
          top_violations: data.top_violations,
          compliance_trends: data.compliance_trends,
          metric_trends: data.metric_trends_b,
          severity_over_time: data.severity_over_time_b,
          sessions: data.sessions_b
        } as any);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedProfile) {
      fetchDashboardData();
    }
    if (compareMode && selectedProfileB) {
      fetchDashboardData(true);
    }
  }, [bucket]);


  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'error';
      case 'High': return 'warning';
      case 'Medium': return 'info';
      case 'Low': return 'success';
      default: return 'default';
    }
  };

  const getComplianceColor = (percentage: number) => {
    if (percentage >= 90) return 'success';
    if (percentage >= 70) return 'warning';
    return 'error';
  };

  const toggleSeverity = (severity: string) => {
    setSelectedSeverities((prev) =>
      prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity]
    );
  };

  const trends = dashboardData?.metric_trends || dashboardData?.compliance_trends || [];
  const filteredTrends = (() => {
    if (!trends || trends.length === 0) return [] as { date: string; compliance_percentage: number }[];
    if (timeRange === 'all') return trends;
    const n = parseInt(timeRange, 10);
    return trends.slice(Math.max(0, trends.length - n));
  })();

  const trendsB = dashboardDataB?.metric_trends || dashboardDataB?.compliance_trends || [];
  const filteredTrendsB = (() => {
    if (!trendsB || trendsB.length === 0) return [] as any[];
    if (timeRange === 'all') return trendsB;
    const n = parseInt(timeRange, 10);
    return trendsB.slice(Math.max(0, trendsB.length - n));
  })();

  const selectedProfileData = profiles.find(p => p.id === selectedProfile);

  const severityCompareData = (() => {
    const a = dashboardData?.severity_compare_grouped as any[] | undefined;
    if (a && a.length) return a;
    const arrA = dashboardData?.severity_over_time || [];
    const arrB = dashboardDataB?.severity_over_time || [];
    const dates = Array.from(new Set([...arrA.map(d=>d.date), ...arrB.map(d=>d.date)]));
    return dates.map((d) => {
      const findA = arrA.find(x=>x.date===d) || { Critical:0, High:0, Medium:0, Low:0 };
      const findB = arrB.find(x=>x.date===d) || { Critical:0, High:0, Medium:0, Low:0 };
      return {
        date: d,
        Critical_A: findA.Critical || 0,
        High_A: findA.High || 0,
        Medium_A: findA.Medium || 0,
        Low_A: findA.Low || 0,
        Critical_B: findB.Critical || 0,
        High_B: findB.High || 0,
        Medium_B: findB.Medium || 0,
        Low_B: findB.Low || 0,
      };
    });
  })();

  const renderTrendTooltip = ({ active, payload, label }: any) => {
    if (!active) return null;
    const p = (payload && payload[0] && payload[0].payload) || {};
    const counts = [
      `Compliant: ${p.compliant_rules ?? '-'}`,
      `Non-compliant: ${p.non_compliant_rules ?? '-'}`,
      `Total: ${p.total_rules ?? '-'}`
    ];
    return (
      <Box sx={{ p: 1, bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
        <Typography variant="caption">{label}</Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          {counts.map((c, i) => (
            <Typography key={i} variant="caption">{c}</Typography>
          ))}
        </Box>
      </Box>
    );
  };

  const severityRank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const ruleSummarySorted = (() => {
    const arr = (dashboardData?.rule_summary || []).filter((r) =>
      !ruleOnlyViolations || r.non_compliant_count > 0
    ).filter((r) =>
      !selectedSeverities.length || (r.severity ? selectedSeverities.includes(r.severity) : true)
    );
    const cmp = (a: any, b: any) => {
      if (ruleSort === 'non_compliant_count') {
        return (a.non_compliant_count - b.non_compliant_count) * (ruleSortOrder === 'asc' ? 1 : -1);
      }
      if (ruleSort === 'severity') {
        const av = severityRank[a.severity || 'Low'] || 0;
        const bv = severityRank[b.severity || 'Low'] || 0;
        return (av - bv) * (ruleSortOrder === 'asc' ? 1 : -1);
      }
      const av = (a.rule_name || '').toLowerCase();
      const bv = (b.rule_name || '').toLowerCase();
      if (av < bv) return ruleSortOrder === 'asc' ? -1 : 1;
      if (av > bv) return ruleSortOrder === 'asc' ? 1 : -1;
      return 0;
    };
    return arr.sort(cmp);
  })();
  const ruleSummaryPaged = (() => {
    const start = (rulePage - 1) * ruleRowsPerPage;
    return ruleSummarySorted.slice(start, start + ruleRowsPerPage);
  })();

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <DashboardIcon sx={{ fontSize: 32, color: 'primary.main' }} />
          <Typography variant="h4" component="h1">
            Compliance Dashboard
          </Typography>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <FormControl sx={{ minWidth: 260 }}>
            <InputLabel>Select Review Profile</InputLabel>
            <Select
              value={selectedProfile}
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
          <Chip label={compareMode ? 'Compare: On' : 'Compare: Off'} onClick={() => setCompareMode(!compareMode)} variant={compareMode ? 'filled' : 'outlined'} />
          {compareMode && (
            <FormControl sx={{ minWidth: 260 }}>
              <InputLabel>Compare Profile</InputLabel>
              <Select
                value={selectedProfileB}
                onChange={(e: SelectChangeEvent<number | ''>) => setSelectedProfileB(e.target.value as number)}
                label="Compare Profile"
              >
                {profiles.map((profile) => (
                  <MenuItem key={profile.id} value={profile.id}>
                    {profile.profile_name} ({profile.compliance_framework})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <Chip label="Save View" onClick={() => {
            if (!selectedProfile) return;
            const key = `compliance_view_${selectedProfile}`;
            const payload = {
              range: timeRange,
              sev: selectedSeverities,
              bucket,
              session_id: selectedSessionId || '',
              compare_profile_id: selectedProfileB || ''
            };
            try { localStorage.setItem(key, JSON.stringify(payload)); } catch {}
          }} />
        </Box>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {!selectedProfile && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Please select a review profile to view compliance dashboard.
        </Alert>
      )}

      {selectedProfile && (
        <>
          {/* Profile Info */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <AssessmentIcon sx={{ color: 'primary.main' }} />
                <Box>
                  <Typography variant="h6">{selectedProfileData?.profile_name || `Profile #${selectedProfile}`}</Typography>
                  {selectedProfileData && (
                    <Typography variant="body2" color="text.secondary">
                      {selectedProfileData.compliance_framework} {selectedProfileData.version}
                    </Typography>
                  )}
                </Box>
              </Box>
            </CardContent>
          </Card>

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress />
            </Box>
          ) : dashboardData ? (
            <>
              {/* Summary Cards */}
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 3 }}>
                <Box sx={{ flex: '1 1 300px', minWidth: '250px' }}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <SecurityIcon sx={{ color: 'primary.main' }} />
                        <Box>
                          <Typography variant="h6">{dashboardData?.summary?.total_rules || 0}</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Total Rules
                          </Typography>
                        </Box>
                      </Box>
                      {loading ? (
                        <Skeleton variant="rectangular" height={40} sx={{ mt: 1 }} />
                      ) : filteredTrends.length > 0 && (
                        <Box sx={{ mt: 1 }}>
                          <ResponsiveContainer width="100%" height={40}>
                            <AreaChart data={filteredTrends} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                              <Area type="monotone" dataKey="total_rules" stroke="#3b82f6" fill="#3b82f620" />
                            </AreaChart>
                          </ResponsiveContainer>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Box>
                
                <Box sx={{ flex: '1 1 300px', minWidth: '250px' }}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <CheckCircleIcon sx={{ color: 'success.main' }} />
                        <Box>
                          <Typography variant="h6">{dashboardData?.summary?.compliant_rules || 0}</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Compliant Rules
                          </Typography>
                        </Box>
                      </Box>
                      {loading ? (
                        <Skeleton variant="rectangular" height={40} sx={{ mt: 1 }} />
                      ) : filteredTrends.length > 0 && (
                        <Box sx={{ mt: 1 }}>
                          <ResponsiveContainer width="100%" height={40}>
                            <AreaChart data={filteredTrends} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                              <Area type="monotone" dataKey="compliant_rules" stroke="#10b981" fill="#10b98120" />
                            </AreaChart>
                          </ResponsiveContainer>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Box>
                
                <Box sx={{ flex: '1 1 300px', minWidth: '250px' }}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <ErrorIcon sx={{ color: 'error.main' }} />
                        <Box>
                          <Typography variant="h6">{dashboardData?.summary?.non_compliant_rules || 0}</Typography>
                          <Typography variant="body2" color="text.secondary">
                            Non-Compliant Rules
                          </Typography>
                        </Box>
                      </Box>
                      {loading ? (
                        <Skeleton variant="rectangular" height={40} sx={{ mt: 1 }} />
                      ) : filteredTrends.length > 0 && (
                        <Box sx={{ mt: 1 }}>
                          <ResponsiveContainer width="100%" height={40}>
                            <AreaChart data={filteredTrends} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                              <Area type="monotone" dataKey="non_compliant_rules" stroke="#ef4444" fill="#ef444420" />
                            </AreaChart>
                          </ResponsiveContainer>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Box>
                
                <Box sx={{ flex: '1 1 300px', minWidth: '250px' }}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <TrendingUpIcon sx={{ color: getComplianceColor(dashboardData.summary.compliance_percentage) === 'success' ? 'success.main' : getComplianceColor(dashboardData.summary.compliance_percentage) === 'warning' ? 'warning.main' : 'error.main' }} />
                        <Box>
                          <Typography variant="h6">
                            {(dashboardData?.summary?.compliance_percentage || 0).toFixed(1)}%
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Compliance Score
                          </Typography>
                        </Box>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={dashboardData?.summary?.compliance_percentage || 0}
                        color={getComplianceColor(dashboardData?.summary?.compliance_percentage || 0) as any}
                        sx={{ mt: 1 }}
                      />
                      {loading ? (
                        <Skeleton variant="rectangular" height={40} sx={{ mt: 1 }} />
                      ) : filteredTrends.length > 0 && (
                        <Box sx={{ mt: 1 }}>
                          <ResponsiveContainer width="100%" height={40}>
                            <AreaChart data={filteredTrends} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                              <Area type="monotone" dataKey="compliance_percentage" stroke="#6366f1" fill="#6366f120" />
                            </AreaChart>
                          </ResponsiveContainer>
                        </Box>
                      )}
                    </CardContent>
                  </Card>
                </Box>
              </Box>

              {/* Compliance Trend */}
              {filteredTrends.length > 0 && (
                <Card sx={{ mb: 3 }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">Compliance Trend</Typography>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <FormControl size="small" sx={{ minWidth: 140 }}>
                          <InputLabel>Range</InputLabel>
                          <Select
                            label="Range"
                            value={timeRange}
                            onChange={(e: SelectChangeEvent<'7' | '30' | '90' | 'all'>) => setTimeRange(e.target.value as any)}
                          >
                            <MenuItem value={'7'}>7</MenuItem>
                            <MenuItem value={'30'}>30</MenuItem>
                            <MenuItem value={'90'}>90</MenuItem>
                            <MenuItem value={'all'}>All</MenuItem>
                          </Select>
                        </FormControl>
                        <FormControl size="small" sx={{ minWidth: 140 }}>
                          <InputLabel>Bucket</InputLabel>
                          <Select
                            label="Bucket"
                            value={bucket}
                            onChange={(e: SelectChangeEvent<'day' | 'week' | 'month'>) => setBucket(e.target.value as any)}
                          >
                            <MenuItem value={'day'}>Day</MenuItem>
                            <MenuItem value={'week'}>Week</MenuItem>
                            <MenuItem value={'month'}>Month</MenuItem>
                          </Select>
                        </FormControl>
                      </Box>
          </Box>
          <Box sx={{ height: 260 }}>
            {loading ? (
              <Skeleton variant="rectangular" height={260} />
            ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={filteredTrends} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.1)" />
                <XAxis dataKey="date" tick={{ fill: '#6b7280' }} />
                <YAxis domain={[0, 100]} tick={{ fill: '#6b7280' }} />
                <Tooltip content={renderTrendTooltip} contentStyle={{ backgroundColor: 'rgba(255,255,255,0.95)', border: '1px solid #e5e7eb' }} />
                <Legend wrapperStyle={{ color: '#6b7280' }} />
                {showLineA && (
                  <Line type="monotone" dataKey="compliance_percentage" stroke="#3b82f6" strokeWidth={3} name="Compliance % (A)" dot={false} />
                )}
                {compareMode && filteredTrendsB.length > 0 && showLineB && (
                  <Line type="monotone" dataKey="compliance_percentage" stroke="#6366f1" strokeWidth={3} name="Compliance % (B)" dot={false} data={filteredTrendsB as any} />
                )}
              </LineChart>
            </ResponsiveContainer>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Chip label={showLineA ? 'Hide A' : 'Show A'} size="small" color={showLineA ? 'secondary' : 'default'} variant={showLineA ? 'filled' : 'outlined'} onClick={() => setShowLineA(v=>!v)} />
            {compareMode && (
              <Chip label={showLineB ? 'Hide B' : 'Show B'} size="small" color={showLineB ? 'secondary' : 'default'} variant={showLineB ? 'filled' : 'outlined'} onClick={() => setShowLineB(v=>!v)} />
            )}
          </Box>
                  </CardContent>
                </Card>
              )}

              {/* Severity Over Time */}
              {severityCompareData && severityCompareData.length > 0 && (
                <Card sx={{ mb: 3 }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ mb: 2 }}>Severity Composition Over Time (Compare)</Typography>
                    <Box sx={{ height: 260 }}>
                      {loading ? (
                        <Skeleton variant="rectangular" height={260} />
                      ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={(timeRange === 'all' ? severityCompareData : severityCompareData.slice(Math.max(0, severityCompareData.length - parseInt(timeRange, 10))))}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.1)" />
                          <XAxis dataKey="date" tick={{ fill: '#6b7280' }} />
                          <YAxis tick={{ fill: '#6b7280' }} />
                          <Tooltip contentStyle={{ backgroundColor: 'rgba(255,255,255,0.95)', border: '1px solid #e5e7eb' }} />
                          <Legend wrapperStyle={{ color: '#6b7280' }} />
                          {selectedSeverities.includes('Critical') && (
                            <Bar dataKey="Critical_A" stackId="A" fill="#e74c3c" />
                          )}
                          {selectedSeverities.includes('High') && (
                            <Bar dataKey="High_A" stackId="A" fill="#f39c12" />
                          )}
                          {selectedSeverities.includes('Medium') && (
                            <Bar dataKey="Medium_A" stackId="A" fill="#00bcd4" />
                          )}
                          {selectedSeverities.includes('Low') && (
                            <Bar dataKey="Low_A" stackId="A" fill="#2ecc71" />
                          )}
                          {compareMode && selectedSeverities.includes('Critical') && (
                            <Bar dataKey="Critical_B" stackId="B" fill="#c0392b" />
                          )}
                          {compareMode && selectedSeverities.includes('High') && (
                            <Bar dataKey="High_B" stackId="B" fill="#d35400" />
                          )}
                          {compareMode && selectedSeverities.includes('Medium') && (
                            <Bar dataKey="Medium_B" stackId="B" fill="#0097a7" />
                          )}
                          {compareMode && selectedSeverities.includes('Low') && (
                            <Bar dataKey="Low_B" stackId="B" fill="#27ae60" />
                          )}
                        </BarChart>
                      </ResponsiveContainer>
                      )}
                    </Box>
                  </CardContent>
                </Card>
              )}

              {/* Violations by Severity */
              }
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 3, mb: 3 }}>
                <Box sx={{ flex: '1 1 400px', minWidth: '300px' }}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                        <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <WarningIcon />
                          Violations by Severity
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1 }}>
                          {['Critical', 'High', 'Medium', 'Low'].map((sev) => (
                            <Chip
                              key={sev}
                              label={sev}
                              color={getSeverityColor(sev) as any}
                              variant={selectedSeverities.includes(sev) ? 'filled' : 'outlined'}
                              size="small"
                              onClick={() => toggleSeverity(sev)}
                            />
                          ))}
                        </Box>
                      </Box>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {Object.entries(dashboardData.violations_by_severity)
                          .filter(([severity]) => selectedSeverities.includes(severity))
                          .map(([severity, count]) => (
                            <Box key={severity} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Chip 
                                label={severity} 
                                color={getSeverityColor(severity) as any}
                                size="small"
                              />
                              <Typography variant="h6">{count}</Typography>
                            </Box>
                          ))}
                      </Box>
                    </CardContent>
                  </Card>
                </Box>
                
                <Box sx={{ flex: '1 1 400px', minWidth: '300px' }}>
                  <Card>
                    <CardContent>
                      <Typography variant="h6" sx={{ mb: 2 }}>
                        Top Violations
                      </Typography>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        {dashboardData?.top_violations
                          ?.filter((v) => selectedSeverities.includes(v.severity))
                          .slice(0, 5)
                          .map((violation, index) => (
                          <Box key={index} onClick={() => { setSelectedViolationRuleId(violation.rule_id); setExamplesOpen(true); }} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', p: 1, bgcolor: 'grey.50', borderRadius: 1, cursor: 'pointer' }}>
                            <Box>
                              <Typography variant="body2" fontWeight="medium">
                                {violation.rule_name}
                              </Typography>
                              <Chip 
                                label={violation.severity} 
                                color={getSeverityColor(violation.severity) as any}
                                size="small"
                              />
                            </Box>
                            <Typography variant="body2" color="text.secondary">
                              {violation.violation_count} violations
                            </Typography>
                          </Box>
                        )) || (
                          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
                            No violations data available
                          </Typography>
                        )}
                      </Box>
                    </CardContent>
                  </Card>
                </Box>
              </Box>

              {/* Per Rule Compliance Summary */}
              {dashboardData?.rule_summary && dashboardData.rule_summary.length > 0 && (
                <Card sx={{ mb: 3 }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                      <Typography variant="h6">Compliance by Rule</Typography>
                      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                        <Chip label={ruleOnlyViolations ? 'Only Violations' : 'All'} onClick={() => { setRulePage(1); setRuleOnlyViolations(v=>!v); }} variant={ruleOnlyViolations ? 'filled' : 'outlined'} size="small" />
                        <FormControl size="small" sx={{ minWidth: 160 }}>
                          <InputLabel>Sort By</InputLabel>
                          <Select label="Sort By" value={ruleSort} onChange={(e: SelectChangeEvent<'non_compliant_count'|'severity'|'rule_name'>) => { setRuleSort(e.target.value as any); setRulePage(1); }}>
                            <MenuItem value={'non_compliant_count'}>Violations</MenuItem>
                            <MenuItem value={'severity'}>Severity</MenuItem>
                            <MenuItem value={'rule_name'}>Rule Name</MenuItem>
                          </Select>
                        </FormControl>
                        <Chip label={ruleSortOrder === 'asc' ? 'Asc' : 'Desc'} onClick={() => { setRuleSortOrder(o=>o==='asc'?'desc':'asc'); setRulePage(1); }} size="small" />
                      </Box>
                    </Box>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      {ruleSummaryPaged.map((r, i) => (
                        <Box key={i} onClick={() => { setSelectedViolationRuleId(r.rule_id); setExamplesOpen(true); }} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', p: 1, bgcolor: 'grey.50', borderRadius: 1, cursor: 'pointer' }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip label={r.severity || 'Unknown'} color={getSeverityColor(r.severity || 'Low') as any} size="small" />
                            <Typography variant="body2" fontWeight="medium">{r.rule_name || `Rule ${r.rule_id}`}</Typography>
                          </Box>
                          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                            <Chip label={`Compliant: ${r.compliant_count}`} size="small" color="success" />
                            <Chip label={`Non-compliant: ${r.non_compliant_count}`} size="small" color="error" />
                            <Chip label={`Violations: ${r.non_compliant_count}`} size="small" variant="outlined" />
                          </Box>
                        </Box>
                      ))}
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
                      <Pagination count={Math.max(1, Math.ceil(ruleSummarySorted.length / ruleRowsPerPage))} page={rulePage} onChange={(_, p) => setRulePage(p)} size="small" />
                    </Box>
                  </CardContent>
                </Card>
              )}

              {/* Compare Mode: Secondary trend */}
              {compareMode && dashboardDataB && (
                <Card sx={{ mb: 3 }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ mb: 2 }}>Compliance Trend (Comparison)</Typography>
                    <Box sx={{ height: 260 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={filteredTrendsB} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.1)" />
                          <XAxis dataKey="date" tick={{ fill: '#6b7280' }} />
                          <YAxis domain={[0, 100]} tick={{ fill: '#6b7280' }} />
                          <Tooltip contentStyle={{ backgroundColor: 'rgba(255,255,255,0.95)', border: '1px solid #e5e7eb' }} />
                          <Legend wrapperStyle={{ color: '#6b7280' }} />
                          <Line type="monotone" dataKey="compliance_percentage" stroke="#6366f1" strokeWidth={3} name="Compliance % (B)" dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </Box>
                  </CardContent>
                </Card>
              )}

            </>
          ) : (
            <Alert severity="info">
              No compliance data available for the selected profile.
            </Alert>
          )}
        </>
      )}
      {/* Violation Examples Modal */}
      {examplesOpen && (
        <Box>
          {/* Lazy fetch examples when modal opens */}
          {(() => {
            if (examplesOpen && selectedViolationRuleId && !examplesLoading && violationExamples.length === 0) {
              setExamplesLoading(true);
              const params = new URLSearchParams({ profile_id: String(selectedProfile), rule_id: String(selectedViolationRuleId), limit: String(10) });
              if (selectedSessionId) params.set('session_id', selectedSessionId);
              fetch(`http://localhost:5001/api/compliance/violations/examples?${params.toString()}`)
                .then(res => res.json())
                .then(data => { setViolationExamples(data.examples || []); })
                .finally(() => setExamplesLoading(false));
            }
            return null;
          })()}
          <Card sx={{ position: 'fixed', left: '50%', top: '50%', transform: 'translate(-50%, -50%)', width: 700, maxWidth: '90vw', zIndex: 1300 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">Violation Examples</Typography>
                <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                  <FormControl size="small" sx={{ minWidth: 220 }}>
                    <InputLabel>Session</InputLabel>
                    <Select
                      label="Session"
                      value={selectedSessionId}
                      onChange={(e: SelectChangeEvent<string>) => { setSelectedSessionId(e.target.value as string); setViolationExamples([]); }}
                    >
                      {(dashboardData?.sessions || []).map((s: any, i: number) => (
                        <MenuItem key={i} value={s.review_session_id}>{String(s.review_session_id || '').slice(0,8)}… — {s.checked_at}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  <Chip label="Close" onClick={() => { setExamplesOpen(false); setViolationExamples([]); setSelectedViolationRuleId(null); }} />
                </Box>
              </Box>
              {examplesLoading ? (
                <Typography variant="body2">Loading...</Typography>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, maxHeight: 400, overflowY: 'auto' }}>
                  {violationExamples.length === 0 ? (
                    <Typography variant="body2" color="text.secondary">No examples available</Typography>
                  ) : (
                    violationExamples.map((ex, idx) => (
                      <Box key={idx} sx={{ p: 1, bgcolor: 'grey.50', borderRadius: 1 }}>
                        <Typography variant="subtitle2">{ex.source_file}</Typography>
                        <Typography variant="caption" color="text.secondary">{ex.action} {ex.protocol} — {ex.source_ip} → {ex.dest_ip}</Typography>
                        <Box sx={{ mt: 1 }}>
                          {(ex.failed_checks || []).slice(0, 4).map((c: any, i: number) => (
                            <Chip key={i} label={typeof c === 'string' ? c : JSON.stringify(c)} size="small" sx={{ mr: 1, mb: 1 }} />
                          ))}
                        </Box>
                        <Box sx={{ mt: 1 }}>
                          {(() => {
                            const ruleId = selectedViolationRuleId;
                            const remediation = (ruleId && remediationLinks[ruleId]) || null;
                            return remediation ? (
                              <Chip label="Remediation" component="a" href={remediation} clickable sx={{ mr: 1 }} />
                            ) : null;
                          })()}
                        </Box>
                      </Box>
                    ))
                  )}
                </Box>
              )}
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
};

const remediationLinks: Record<number, string> = {
};

export default ComplianceDashboard;
