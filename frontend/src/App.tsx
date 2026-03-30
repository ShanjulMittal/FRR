import React, { useMemo, useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Box } from '@mui/material';
import Navbar from './components/Navbar';
import { 
  Dashboard, 
  Uploads, 
  CMDB, 
  VLANs, 
  Compliance, 
  ObjectGroups,
  ServiceMappings
} from './pages';
import RulesSimple from './pages/RulesSimple';
import NormalizedRules from './pages/NormalizedRules';
import ComplianceRules from './pages/ComplianceRules';
import ReviewProfiles from './pages/ReviewProfiles';
import ComplianceDashboard from './pages/ComplianceDashboard';
import ReviewResults from './pages/ReviewResults';
import CustomFields from './pages/CustomFields';

export type ThemeName = 'light' | 'dark' | 'contrast' | 'ocean' | 'solarized' | 'dracula' | 'sunset' | 'forest';
export type ViewDensity = 'comfortable' | 'compact';
export type Accent = 'vibrant' | 'muted';
export type Corners = 'rounded' | 'sharp';
export type TypeScale = 'normal' | 'large' | 'xlarge';
export type ChipStyle = 'filled' | 'outlined';
export type Elevation = boolean;
export type Glass = boolean;

export const UISettingsContext = React.createContext<{
  themeName: ThemeName;
  setThemeName: (n: ThemeName) => void;
  density: ViewDensity;
  setDensity: (d: ViewDensity) => void;
  accent: Accent;
  setAccent: (a: Accent) => void;
  corners: Corners;
  setCorners: (c: Corners) => void;
  gradient: boolean;
  setGradient: (g: boolean) => void;
  typeScale: TypeScale;
  setTypeScale: (t: TypeScale) => void;
  chipStyle: ChipStyle;
  setChipStyle: (c: ChipStyle) => void;
  animations: boolean;
  setAnimations: (a: boolean) => void;
  primaryColor: string;
  setPrimaryColor: (c: string) => void;
  secondaryColor: string;
  setSecondaryColor: (c: string) => void;
  elevated: Elevation;
  setElevated: (e: Elevation) => void;
  glass: Glass;
  setGlass: (g: Glass) => void;
}>({ themeName: 'light', setThemeName: () => {}, density: 'comfortable', setDensity: () => {}, accent: 'vibrant', setAccent: () => {}, corners: 'rounded', setCorners: () => {}, gradient: true, setGradient: () => {}, typeScale: 'normal', setTypeScale: () => {}, chipStyle: 'filled', setChipStyle: () => {}, animations: true, setAnimations: () => {}, primaryColor: '', setPrimaryColor: () => {}, secondaryColor: '', setSecondaryColor: () => {}, elevated: true, setElevated: () => {}, glass: false, setGlass: () => {} });

const buildTheme = (name: ThemeName, density: ViewDensity, accent: Accent, corners: Corners, elevated: boolean, typeScale: TypeScale, chipStyle: ChipStyle, animations: boolean, primaryColor: string, secondaryColor: string, glass: Glass) => {
  const isCompact = density === 'compact';
  const radius = corners === 'rounded' ? 14 : 6;
  const baseFont = typeScale === 'xlarge' ? 18 : typeScale === 'large' ? 16 : 14;
  const base = {
    typography: {
      fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
      fontSize: baseFont,
      h3: { fontWeight: 700 },
      h4: { fontWeight: 700 },
      h5: { fontWeight: 600 },
      h6: { fontWeight: 600 },
      subtitle1: { fontWeight: 500 }
    },
    shape: { borderRadius: radius },
    components: {
      MuiCard: { styleOverrides: { root: { borderRadius: radius + 2, boxShadow: elevated ? '0 10px 30px rgba(0,0,0,0.08)' : 'none', backgroundColor: glass ? ((name === 'dark' || name === 'dracula') ? 'rgba(30,34,39,0.5)' : 'rgba(255,255,255,0.6)') : undefined, backdropFilter: glass ? 'saturate(180%) blur(8px)' : undefined, border: glass ? '1px solid rgba(255,255,255,0.2)' : undefined } } },
      MuiButton: { defaultProps: { size: isCompact ? 'small' : 'medium' }, styleOverrides: { root: { textTransform: 'none', fontWeight: 600 } } },
      MuiTable: { defaultProps: { size: isCompact ? 'small' : 'medium' } },
      MuiTableCell: { styleOverrides: { root: { padding: isCompact ? '6px 10px' : '12px 16px' } } },
      MuiChip: { styleOverrides: { root: { fontWeight: 600 } }, defaultProps: { variant: chipStyle } },
      MuiButtonBase: { defaultProps: { disableRipple: !animations } }
    },
    transitions: animations ? undefined : { duration: { shortest: 0, shorter: 0, short: 0, standard: 0, complex: 0, enteringScreen: 0, leavingScreen: 0 } }
  } as const;
  const pick = (p: any) => createTheme({ ...base, palette: p });
  let themeObj;
  switch (name) {
    case 'dark':
      themeObj = pick({ mode: 'dark', primary: { main: '#90caf9' }, secondary: { main: '#f48fb1' }, success: { main: '#66bb6a' }, warning: { main: '#ffa726' }, error: { main: '#ef5350' }, info: { main: '#26c6da' }, background: { default: '#101418', paper: '#141a1f' } });
      break;
    case 'contrast':
      themeObj = pick({ mode: 'light', primary: { main: '#000000' }, secondary: { main: '#ffdd00' }, success: { main: '#005f00' }, warning: { main: '#b35c00' }, error: { main: '#8b0000' }, info: { main: '#003366' }, background: { default: '#ffffff' } });
      break;
    case 'ocean':
      themeObj = pick({ mode: 'light', primary: { main: '#006d77' }, secondary: { main: '#83c5be' }, success: { main: '#2a9d8f' }, warning: { main: '#e9c46a' }, error: { main: '#e76f51' }, info: { main: '#00bcd4' }, background: { default: '#edf6f9' } });
      break;
    case 'solarized':
      themeObj = pick({ mode: 'light', primary: { main: '#268bd2' }, secondary: { main: '#2aa198' }, success: { main: '#859900' }, warning: { main: '#b58900' }, error: { main: '#dc322f' }, info: { main: '#6c71c4' }, background: { default: '#fdf6e3' } });
      break;
    case 'dracula':
      themeObj = pick({ mode: 'dark', primary: { main: '#bd93f9' }, secondary: { main: '#ff79c6' }, success: { main: '#50fa7b' }, warning: { main: '#f1fa8c' }, error: { main: '#ff5555' }, info: { main: '#8be9fd' }, background: { default: '#282a36', paper: '#1e2029' } });
      break;
    case 'sunset':
      themeObj = pick({ mode: 'light', primary: { main: '#ff6b6b' }, secondary: { main: '#ffd93d' }, success: { main: '#4ecdc4' }, warning: { main: '#f7b267' }, error: { main: '#ef476f' }, info: { main: '#118ab2' }, background: { default: '#fff5e6' } });
      break;
    case 'forest':
      themeObj = pick({ mode: 'light', primary: { main: '#2b9348' }, secondary: { main: '#55a630' }, success: { main: '#95d5b2' }, warning: { main: '#e9c46a' }, error: { main: '#e76f51' }, info: { main: '#2a9d8f' }, background: { default: '#e9f5ec' } });
      break;
    case 'light':
    default:
      themeObj = pick({ mode: 'light', primary: { main: '#4c9aff' }, secondary: { main: '#ff6f91' }, success: { main: '#2ecc71' }, warning: { main: '#f39c12' }, error: { main: '#e74c3c' }, info: { main: '#00bcd4' }, background: { default: '#f4f7fb' } });
      break;
  }
  if (accent === 'muted') {
    const p = themeObj.palette;
    const lm = p.mode === 'light';
    p.primary = { main: lm ? '#6fa8ff' : '#8bbcfb' } as any;
    p.secondary = { main: lm ? '#b3e5fc' : '#b57bd6' } as any;
  }
  if (primaryColor) {
    (themeObj.palette as any).primary = { ...(themeObj.palette.primary as any), main: primaryColor };
  }
  if (secondaryColor) {
    (themeObj.palette as any).secondary = { ...(themeObj.palette.secondary as any), main: secondaryColor };
  }
  return themeObj;
};

function App() {
  const [themeName, setThemeName] = useState<ThemeName>('light');
  const [density, setDensity] = useState<ViewDensity>('comfortable');
  const [accent, setAccent] = useState<Accent>('vibrant');
  const [corners, setCorners] = useState<Corners>('rounded');
  const [gradient, setGradient] = useState<boolean>(true);
  const [elevated, setElevated] = useState<boolean>(true);
  const [typeScale, setTypeScale] = useState<TypeScale>('normal');
  const [chipStyle, setChipStyle] = useState<ChipStyle>('filled');
  const [animations, setAnimations] = useState<boolean>(true);
  const [primaryColor, setPrimaryColor] = useState<string>('');
  const [secondaryColor, setSecondaryColor] = useState<string>('');
  const [glass, setGlass] = useState<Glass>(false);

  useEffect(() => {
    try {
      const tn = (localStorage.getItem('app_theme') as ThemeName) || 'light';
      const dv = (localStorage.getItem('app_density') as ViewDensity) || 'comfortable';
      setThemeName(tn);
      setDensity(dv);
      const ac = (localStorage.getItem('app_accent') as Accent) || 'vibrant';
      const cr = (localStorage.getItem('app_corners') as Corners) || 'rounded';
      const gr = localStorage.getItem('app_gradient');
      const el = localStorage.getItem('app_elevated');
      setAccent(ac);
      setCorners(cr);
      setGradient(gr ? gr === 'true' : true);
      setElevated(el ? el === 'true' : true);
      const ts = (localStorage.getItem('app_type_scale') as TypeScale) || 'normal';
      const cs = (localStorage.getItem('app_chip_style') as ChipStyle) || 'filled';
      const an = localStorage.getItem('app_animations');
      const pc = localStorage.getItem('app_primary_color') || '';
      const sc = localStorage.getItem('app_secondary_color') || '';
      const gl = localStorage.getItem('app_glass');
      setTypeScale(ts);
      setChipStyle(cs);
      setAnimations(an ? an === 'true' : true);
      setPrimaryColor(pc);
      setSecondaryColor(sc);
      setGlass(gl ? gl === 'true' : false);
    } catch {}
  }, []);

  const theme = useMemo(() => buildTheme(themeName, density, accent, corners, elevated, typeScale, chipStyle, animations, primaryColor, secondaryColor, glass), [themeName, density, accent, corners, elevated, typeScale, chipStyle, animations, primaryColor, secondaryColor, glass]);

  const ctx = useMemo(() => ({
    themeName,
    setThemeName: (n: ThemeName) => { setThemeName(n); try { localStorage.setItem('app_theme', n); } catch {} },
    density,
    setDensity: (d: ViewDensity) => { setDensity(d); try { localStorage.setItem('app_density', d); } catch {} },
    accent,
    setAccent: (a: Accent) => { setAccent(a); try { localStorage.setItem('app_accent', a); } catch {} },
    corners,
    setCorners: (c: Corners) => { setCorners(c); try { localStorage.setItem('app_corners', c); } catch {} },
    gradient,
    setGradient: (g: boolean) => { setGradient(g); try { localStorage.setItem('app_gradient', String(g)); } catch {} },
    typeScale,
    setTypeScale: (t: TypeScale) => { setTypeScale(t); try { localStorage.setItem('app_type_scale', t); } catch {} },
    chipStyle,
    setChipStyle: (c: ChipStyle) => { setChipStyle(c); try { localStorage.setItem('app_chip_style', c); } catch {} },
    animations,
    setAnimations: (a: boolean) => { setAnimations(a); try { localStorage.setItem('app_animations', String(a)); } catch {} },
    primaryColor,
    setPrimaryColor: (c: string) => { setPrimaryColor(c); try { localStorage.setItem('app_primary_color', c); } catch {} },
    secondaryColor,
    setSecondaryColor: (c: string) => { setSecondaryColor(c); try { localStorage.setItem('app_secondary_color', c); } catch {} },
    elevated,
    setElevated: (e: Elevation) => { setElevated(e); try { localStorage.setItem('app_elevated', String(e)); } catch {} },
    glass,
    setGlass: (g: Glass) => { setGlass(g); try { localStorage.setItem('app_glass', String(g)); } catch {} }
  }), [themeName, density, accent, corners, gradient, typeScale, chipStyle, animations, primaryColor, secondaryColor, elevated, glass]);

  return (
    <UISettingsContext.Provider value={ctx}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Router>
          <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: gradient ? (theme.palette.mode === 'light' ? 'linear-gradient(180deg, #f4f7fb 0%, #eef3ff 60%, #f9f9ff 100%)' : 'linear-gradient(180deg, #1e2029 0%, #101418 100%)') : 'none' }}>
            <Navbar />
            <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/uploads" element={<Uploads />} />
                <Route path="/rules" element={<RulesSimple />} />
                <Route path="/normalized-rules" element={<NormalizedRules />} />
                <Route path="/cmdb" element={<CMDB />} />
                <Route path="/vlans" element={<VLANs />} />
                <Route path="/object-groups" element={<ObjectGroups />} />
                <Route path="/service-mappings" element={<ServiceMappings />} />
                <Route path="/compliance" element={<Navigate to="/compliance-dashboard" replace />} />
                <Route path="/compliance-rules" element={<ComplianceRules />} />
                <Route path="/review-profiles" element={<ReviewProfiles />} />
                <Route path="/compliance-dashboard" element={<ComplianceDashboard />} />
                <Route path="/review-results" element={<ReviewResults />} />
                <Route path="/custom-fields" element={<CustomFields />} />
              </Routes>
            </Box>
          </Box>
        </Router>
      </ThemeProvider>
    </UISettingsContext.Provider>
  );
}

export default App;
