import React, { useContext, useState } from 'react';
import { AppBar, Toolbar, Typography, Box, Tabs, Tab, Button, Menu, MenuItem, Divider, ListSubheader, Switch } from '@mui/material';
import PaletteIcon from '@mui/icons-material/Palette';
import { Dashboard as DashboardIcon, Upload as UploadIcon, Security as SecurityIcon, Storage as StorageIcon, NetworkCheck as NetworkIcon, Assessment as ComplianceIcon, Group as GroupIcon, Rule as RuleIcon, Assignment as AssignmentIcon, BarChart as DashboardChartIcon, PlaylistAddCheck as ReviewResultsIcon, Settings as SettingsIcon, Router as RouterIcon } from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { UISettingsContext, ThemeName, ViewDensity, Accent, Corners, TypeScale, ChipStyle } from '../App';
const Navbar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { themeName, setThemeName, density, setDensity, accent, setAccent, corners, setCorners, gradient, setGradient, typeScale, setTypeScale, chipStyle, setChipStyle, animations, setAnimations, primaryColor, setPrimaryColor, secondaryColor, setSecondaryColor, elevated, setElevated, glass, setGlass } = useContext(UISettingsContext);
  const [themeAnchor, setThemeAnchor] = useState<null | HTMLElement>(null);
  const themeOpen = Boolean(themeAnchor);

  const navItems = [
    { label: 'Dashboard', path: '/', icon: <DashboardIcon /> },
    { label: 'Uploads', path: '/uploads', icon: <UploadIcon /> },
    { label: 'Rules', path: '/rules', icon: <SecurityIcon /> },
    { label: 'Normalized Rules', path: '/normalized-rules', icon: <RuleIcon /> },
    { label: 'CMDB', path: '/cmdb', icon: <StorageIcon /> },
    { label: 'VLANs', path: '/vlans', icon: <NetworkIcon /> },
    { label: 'Object Groups', path: '/object-groups', icon: <GroupIcon /> },
    { label: 'Service Mappings', path: '/service-mappings', icon: <RouterIcon /> },
    { label: 'Compliance Rules', path: '/compliance-rules', icon: <RuleIcon /> },
    { label: 'Review Profiles', path: '/review-profiles', icon: <AssignmentIcon /> },
    { label: 'Compliance Dashboard', path: '/compliance-dashboard', icon: <DashboardChartIcon /> },
    { label: 'Review Results', path: '/review-results', icon: <ReviewResultsIcon /> },
    { label: 'Custom Fields', path: '/custom-fields', icon: <SettingsIcon /> },
  ];
  const tabIndex = Math.max(0, navItems.findIndex((n) => n.path === location.pathname));

  return (
    <AppBar position="sticky" elevation={0} sx={{ bgcolor: 'background.paper', color: 'text.primary', borderBottom: '1px solid', borderColor: 'divider' }}>
      <Toolbar sx={{ minHeight: 64 }}>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontWeight: 700 }}>
          Firewall Rule Review
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, minWidth: 0 }}>
          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Tabs
              value={tabIndex}
              onChange={(_, idx) => navigate(navItems[idx].path)}
              variant="scrollable"
              scrollButtons="auto"
              allowScrollButtonsMobile
              textColor="primary"
              indicatorColor="primary"
              sx={{
                maxWidth: { xs: '60vw', sm: '65vw', md: '70vw' },
                '.MuiTab-root': { minHeight: 40, paddingX: 1.25 },
              }}
            >
              {navItems.map((item) => (
                <Tab key={item.path} icon={item.icon} iconPosition="start" label={item.label} />
              ))}
            </Tabs>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', ml: 2 }}>
            <Button
              startIcon={<PaletteIcon />}
              variant={themeOpen ? 'contained' : 'outlined'}
              color="primary"
              size="small"
              onClick={(e) => setThemeAnchor(e.currentTarget)}
            >
              Theme
            </Button>
            <Menu
              open={themeOpen}
              anchorEl={themeAnchor}
              onClose={() => setThemeAnchor(null)}
              anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
              transformOrigin={{ vertical: 'top', horizontal: 'right' }}
            >
              <ListSubheader disableSticky>Theme</ListSubheader>
              {[
                ['light', 'Light'],
                ['dark', 'Dark'],
                ['contrast', 'High Contrast'],
                ['ocean', 'Ocean'],
                ['solarized', 'Solarized'],
                ['dracula', 'Dracula'],
                ['sunset', 'Sunset'],
                ['forest', 'Forest']
              ].map(([val, label]) => (
                <MenuItem key={val} selected={themeName === (val as ThemeName)} onClick={() => { setThemeName(val as ThemeName); setPrimaryColor(''); setSecondaryColor(''); }}>
                  {label}
                </MenuItem>
              ))}
              <Divider />
              <ListSubheader disableSticky>View</ListSubheader>
              {[
                ['comfortable', 'Comfortable'],
                ['compact', 'Compact']
              ].map(([val, label]) => (
                <MenuItem key={val} selected={density === (val as ViewDensity)} onClick={() => { setDensity(val as ViewDensity); }}>
                  {label}
                </MenuItem>
              ))}
              <Divider />
              <ListSubheader disableSticky>Typography</ListSubheader>
              {[
                ['normal', 'Normal'],
                ['large', 'Large'],
                ['xlarge', 'Extra Large']
              ].map(([val, label]) => (
                <MenuItem key={val} selected={typeScale === (val as TypeScale)} onClick={() => { setTypeScale(val as TypeScale); }}>
                  {label}
                </MenuItem>
              ))}
              <Divider />
              <ListSubheader disableSticky>Accent</ListSubheader>
              {[
                ['vibrant', 'Vibrant'],
                ['muted', 'Muted']
              ].map(([val, label]) => (
                <MenuItem key={val} selected={accent === (val as Accent)} onClick={() => { setAccent(val as Accent); }}>
                  {label}
                </MenuItem>
              ))}
              <Divider />
              <ListSubheader disableSticky>Corners</ListSubheader>
              {[
                ['rounded', 'Rounded'],
                ['sharp', 'Sharp']
              ].map(([val, label]) => (
                <MenuItem key={val} selected={corners === (val as Corners)} onClick={() => { setCorners(val as Corners); }}>
                  {label}
                </MenuItem>
              ))}
              <Divider />
              <ListSubheader disableSticky>Chips</ListSubheader>
              {[
                ['filled', 'Filled'],
                ['outlined', 'Outlined']
              ].map(([val, label]) => (
                <MenuItem key={val} selected={chipStyle === (val as ChipStyle)} onClick={() => { setChipStyle(val as ChipStyle); }}>
                  {label}
                </MenuItem>
              ))}
              <Divider />
              <MenuItem disableRipple>
                <Switch checked={gradient} onChange={(e) => setGradient(e.target.checked)} />
                Gradient Background
              </MenuItem>
              <MenuItem disableRipple>
                <Switch checked={animations} onChange={(e) => setAnimations(e.target.checked)} />
                Animations
              </MenuItem>
              <MenuItem disableRipple>
                <Switch checked={elevated} onChange={(e) => setElevated(e.target.checked)} />
                Elevated Cards
              </MenuItem>
              <MenuItem disableRipple>
                <Switch checked={glass} onChange={(e) => setGlass(e.target.checked)} />
                Glass Effect
              </MenuItem>
              <Divider />
              <ListSubheader disableSticky>Primary Color</ListSubheader>
              <MenuItem disableRipple>
                <input type="color" value={primaryColor || '#4c9aff'} onChange={(e) => setPrimaryColor(e.target.value)} style={{ width: 36, height: 24, padding: 0, border: 'none', background: 'none' }} />
                <Box sx={{ ml: 1 }}>Pick</Box>
              </MenuItem>
              <ListSubheader disableSticky>Secondary Color</ListSubheader>
              <MenuItem disableRipple>
                <input type="color" value={secondaryColor || '#ff6f91'} onChange={(e) => setSecondaryColor(e.target.value)} style={{ width: 36, height: 24, padding: 0, border: 'none', background: 'none' }} />
                <Box sx={{ ml: 1 }}>Pick</Box>
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => {
                setThemeName('light' as ThemeName);
                setDensity('comfortable');
                setTypeScale('normal');
                setChipStyle('filled');
                setAccent('vibrant');
                setCorners('rounded');
                setGradient(true);
                setAnimations(true);
                setPrimaryColor('');
                setSecondaryColor('');
                setElevated(true);
                setGlass(false);
                setThemeAnchor(null);
              }}>
                Reset to defaults
              </MenuItem>
            </Menu>
          </Box>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
