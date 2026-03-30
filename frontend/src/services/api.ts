import axios from 'axios';

// Base API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

const api = axios.create({
  baseURL: API_BASE_URL,
});

// API response types
export interface FirewallRule {
  id: number;
  source_file: string;
  line_number: number;
  rule_text: string;
  parsed_source?: string;
  parsed_destination?: string;
  parsed_service?: string;
  parsed_action?: string;
  created_at: string;
}

export interface CMDBAsset {
  id: number;
  ip_address: string;
  hostname: string;
  owner: string;
  environment: string;
  asset_type: string;
  location?: string;
  created_at: string;
}

export interface VLANNetwork {
  id: number;
  vlan_id: number;
  name: string;
  subnet: string;
  description?: string;
  created_at: string;
}

export interface ObjectGroup {
  id: number;
  name: string;
  description?: string;
  created_at: string;
}

export interface UploadResponse {
  message: string;
  file_id?: string;
  processed_records?: number;
}

export interface CustomField {
  id?: number;
  field_name: string;
  display_name: string;
  field_type: 'text' | 'number' | 'boolean' | 'date';
  file_type: 'firewall' | 'cmdb' | 'vlan';
  is_required: boolean;
  default_value?: string;
  validation_rules?: string;
  description?: string;
  created_by: string;
  created_at?: string;
  updated_at?: string;
}

export interface CustomRule {
  id?: number;
  field_id: number;
  rule_name: string;
  condition_type: 'equals' | 'greater_than' | 'less_than' | 'contains' | 'regex';
  condition_value: string;
  action: 'flag' | 'alert' | 'block' | 'highlight';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message?: string;
  is_active: boolean;
  created_by: string;
  created_at?: string;
  updated_at?: string;
}

// API service functions
export const apiService = {
  // Health check
  healthCheck: async () => {
    const response = await api.get('/health');
    return response.data;
  },

  // Firewall Rules
  getRules: async (): Promise<FirewallRule[]> => {
    const response = await api.get('/api/rules');
    return response.data;
  },

  // CMDB Assets
  getCMDBAssets: async (): Promise<CMDBAsset[]> => {
    const response = await api.get('/api/cmdb');
    return response.data;
  },

  // VLAN Networks
  getVLANs: async (): Promise<VLANNetwork[]> => {
    const response = await api.get('/api/vlans');
    return response.data;
  },

  // Object Groups
  getObjectGroups: async (): Promise<ObjectGroup[]> => {
    const response = await api.get('/api/object-groups');
    return response.data;
  },

  // File Upload
  uploadFile: async (file: File, fileType: string, columnMapping?: { [key: string]: any }): Promise<UploadResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('file_type', fileType);
    if (columnMapping) {
      formData.append('column_mapping', JSON.stringify(columnMapping));
    }
    const response = await api.post('/api/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  // Dashboard Statistics
  getDashboardStats: async () => {
    const response = await api.get('/api/dashboard/stats');
    return response.data;
  },

  // Compliance Metrics
  getComplianceMetrics: async () => {
    const response = await api.get('/api/compliance/metrics');
    return response.data;
  },

  // Custom Fields
  getCustomFields: async (): Promise<CustomField[]> => {
    const response = await api.get('/api/custom-fields');
    return response.data.data;
  },

  createCustomField: async (field: Omit<CustomField, 'id' | 'created_at' | 'updated_at'>): Promise<CustomField> => {
    const response = await api.post('/api/custom-fields', field);
    return response.data.data;
  },

  updateCustomField: async (id: number, field: Partial<CustomField>): Promise<CustomField> => {
    const response = await api.put(`/api/custom-fields/${id}`, field);
    return response.data.data;
  },

  deleteCustomField: async (id: number): Promise<void> => {
    await api.delete(`/api/custom-fields/${id}`);
  },

  getCustomFieldsByType: async (fileType: string): Promise<CustomField[]> => {
    const response = await api.get(`/api/custom-fields/file-type/${fileType}`);
    return response.data.data;
  },

  // Custom Rules
  getCustomRules: async (): Promise<CustomRule[]> => {
    const response = await api.get('/api/custom-rules');
    return response.data.data;
  },

  createCustomRule: async (rule: Omit<CustomRule, 'id' | 'created_at' | 'updated_at'>): Promise<CustomRule> => {
    const response = await api.post('/api/custom-rules', rule);
    return response.data.data;
  },

  updateCustomRule: async (id: number, rule: Partial<CustomRule>): Promise<CustomRule> => {
    const response = await api.put(`/api/custom-rules/${id}`, rule);
    return response.data.data;
  },

  deleteCustomRule: async (id: number): Promise<void> => {
    await api.delete(`/api/custom-rules/${id}`);
  },

  evaluateCustomRules: async (fieldName: string, value: any): Promise<any[]> => {
    const response = await api.post('/api/custom-rules/evaluate', { field_name: fieldName, value });
    return response.data.data;
  },
};

export default api;
