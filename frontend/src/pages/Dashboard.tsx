import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  Chip,
  CircularProgress,
  Alert,
  Button
} from '@mui/material';
import {
  Security,
  Storage,
  NetworkCheck,
  Assessment,
  TrendingUp,
  Warning,
  CheckCircle
} from '@mui/icons-material';
import { apiService } from '../services/api';

interface DashboardStats {
  total_rules: number;
  total_assets: number;
  total_vlans: number;
  compliance_score: number;
}

interface ReviewSummary {
  review_session_id: string;
  profile: { id: number | null; name: string | null; framework: string | null };
  execution_time: string | null;
  statistics: {
    total_rules_scanned: number;
    total_checks_performed: number;
    compliant_count: number;
    non_compliant_count: number;
    compliance_percentage: number;
    findings_by_rule: { [key: string]: number };
    severity_breakdown: { Critical: number; High: number; Medium: number; Low: number };
  };
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reviewSummary, setReviewSummary] = useState<ReviewSummary | null>(null);
  const [latestSession, setLatestSession] = useState<{ review_session_id: string; profile_name: string; started_at: string | null; total_checks: number } | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        const data = await apiService.getDashboardStats();
        setStats(data);
        setError(null);
      } catch (err) {
        setError('Failed to load dashboard statistics');
        console.error('Dashboard stats error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    fetchLatestReviewSummary();
  }, []);

  const fetchLatestReviewSummary = async () => {
    try {
      const resSessions = await fetch('http://localhost:5001/api/reviews/sessions');
      const sessionsJson = await resSessions.json();
      const sessions = sessionsJson.data || [];
      if (sessions.length === 0) return;
      const latest = sessions[0];
      setLatestSession(latest);
      const resSummary = await fetch(`http://localhost:5001/api/reviews/summary/${latest.review_session_id}`);
      const summaryJson = await resSummary.json();
      if (summaryJson.success && summaryJson.data) {
        setReviewSummary(summaryJson.data);
      }
    } catch (e) {
      console.error('Latest review summary fetch error:', e);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box p={3}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  const mockRecentActivity = [
    { id: 1, action: 'Uploaded firewall config', file: 'cisco_asa_rules.txt', time: '2 hours ago' },
    { id: 2, action: 'Updated CMDB assets', file: 'server_inventory.csv', time: '4 hours ago' },
    { id: 3, action: 'Compliance scan completed', file: 'security_audit.json', time: '1 day ago' },
  ];

  return (
    <Box p={3} sx={{ position: 'relative', zIndex: (theme) => theme.zIndex.tooltip + 2, color: 'text.primary' }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 800 }}>Dashboard</Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Overview of assets, rules, and compliance health
        </Typography>
      </Box>
      
      {/* Statistics Cards */}
      <Box display="flex" flexWrap="wrap" gap={3} sx={{ mb: 4 }}>
        <Box flex="1 1 250px" minWidth="250px">
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography gutterBottom>Total Rules</Typography>
                  <Typography variant="h4">{stats?.total_rules || 0}</Typography>
                </Box>
                <Security sx={{ fontSize: 40, color: 'primary.main' }} />
              </Box>
            </CardContent>
          </Card>
        </Box>
        
        <Box flex="1 1 250px" minWidth="250px">
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography gutterBottom>CMDB Assets</Typography>
                  <Typography variant="h4">
                    {stats?.total_assets || 0}
                  </Typography>
                </Box>
                <Storage sx={{ fontSize: 40, color: 'secondary.main' }} />
              </Box>
            </CardContent>
          </Card>
        </Box>
        
        <Box flex="1 1 250px" minWidth="250px">
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography gutterBottom>VLANs</Typography>
                  <Typography variant="h4">
                    {stats?.total_vlans || 0}
                  </Typography>
                </Box>
                <NetworkCheck sx={{ fontSize: 40, color: 'info.main' }} />
              </Box>
            </CardContent>
          </Card>
        </Box>
        
        <Box flex="1 1 250px" minWidth="250px">
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography gutterBottom>Compliance Score</Typography>
                  <Typography variant="h4">
                    {(reviewSummary?.statistics?.compliance_percentage ?? stats?.compliance_score ?? 0)}%
                  </Typography>
                </Box>
                <Assessment sx={{ fontSize: 40, color: 'success.main' }} />
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Box>

      {reviewSummary && (
        <Box display="flex" flexWrap="wrap" gap={3} sx={{ mb: 4 }}>
          <Box flex="1 1 250px" minWidth="250px">
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Non-Compliant
                </Typography>
                <Typography variant="h5" color="error">
                  {reviewSummary.statistics.non_compliant_count}
                </Typography>
              </CardContent>
            </Card>
          </Box>
          <Box flex="1 1 250px" minWidth="250px">
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Compliant
                </Typography>
                <Typography variant="h5" color="success.main">
                  {reviewSummary.statistics.compliant_count}
                </Typography>
              </CardContent>
            </Card>
          </Box>
          <Box flex="1 1 250px" minWidth="250px">
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Checks Performed
                </Typography>
                <Typography variant="h5">
                  {reviewSummary.statistics.total_checks_performed}
                </Typography>
              </CardContent>
            </Card>
          </Box>
        </Box>
      )}

      {reviewSummary && (
        <Box sx={{ mb: 4 }}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Severity Breakdown
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              {Object.entries(reviewSummary.statistics.severity_breakdown).map(([severity, count]) => (
                <Chip
                  key={severity}
                  label={`${severity}: ${count}`}
                  color={severity === 'Critical' ? 'error' : severity === 'High' ? 'warning' : severity === 'Medium' ? 'info' : 'success'}
                  variant="outlined"
                />
              ))}
            </Box>
          </Paper>
        </Box>
      )}

      {latestSession && (
        <Box sx={{ mb: 4 }}>
          <Paper sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box>
              <Typography variant="h6">Latest Review</Typography>
              <Typography variant="body2" color="text.secondary">
                {latestSession.profile_name} • {latestSession.started_at ? new Date(latestSession.started_at).toLocaleString() : 'N/A'} • {latestSession.total_checks} checks
              </Typography>
            </Box>
            <Button variant="outlined" onClick={() => (window.location.href = '/review-results')}>View Results</Button>
          </Paper>
        </Box>
      )}

      <Box display="flex" flexWrap="wrap" gap={3}>
        {/* Recent Activity */}
        <Box flex="1 1 400px" minWidth="400px">
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Recent Activity
            </Typography>
            <List>
              {mockRecentActivity.map((activity) => (
                <ListItem key={activity.id}>
                  <ListItemText
                    primary={activity.action}
                    secondary={`${activity.file} • ${activity.time}`}
                  />
                </ListItem>
              ))}
            </List>
          </Paper>
        </Box>

        {/* System Status */}
        <Box flex="1 1 400px" minWidth="400px">
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              System Status
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Box display="flex" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                <Typography>API Connection</Typography>
                <Chip
                  icon={<CheckCircle />}
                  label="Connected"
                  color="success"
                  size="small"
                />
              </Box>
              <Box display="flex" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                <Typography>Database</Typography>
                <Chip
                  icon={<CheckCircle />}
                  label="Online"
                  color="success"
                  size="small"
                />
              </Box>
              <Box display="flex" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                <Typography>Last Backup</Typography>
                <Chip
                  icon={<TrendingUp />}
                  label="2 hours ago"
                  color="info"
                  size="small"
                />
              </Box>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Typography>Security Alerts</Typography>
                <Chip
                  icon={<Warning />}
                  label="3 pending"
                  color="warning"
                  size="small"
                />
              </Box>
            </Box>
          </Paper>
        </Box>
      </Box>
    </Box>
  );
};

export default Dashboard;
