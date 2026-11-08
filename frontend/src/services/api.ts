import axios from 'axios';
import {
  ScanDetail,
  ScanListResponse,
  VerifyReportResponse,
  SystemStatusResponse,
  StatsOverviewResponse,
  RiskReport
} from '../types';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const scanUrl = async (url: string): Promise<ScanDetail> => {
  const response = await api.post<ScanDetail>('/scans/url', { url });
  return response.data;
};

export const scanMessage = async (content: string): Promise<ScanDetail> => {
  const response = await api.post<ScanDetail>('/scans/message', { content });
  return response.data;
};

export const getScans = async (params?: {
  query?: string;
  risk_level?: string;
  scan_type?: string;
  limit?: number;
  offset?: number;
}): Promise<ScanListResponse> => {
  const response = await api.get<ScanListResponse>('/scans', { params });
  return response.data;
};

export const getScanById = async (scanId: string): Promise<ScanDetail> => {
  const response = await api.get<ScanDetail>(`/scans/${scanId}`);
  return response.data;
};

export const getReportById = async (reportId: string): Promise<RiskReport> => {
  const response = await api.get<RiskReport>(`/reports/${reportId}`);
  return response.data;
};

export const verifyReport = async (
  reportId: string,
  simulatedTamperedSummary?: string
): Promise<VerifyReportResponse> => {
  const response = await api.post<VerifyReportResponse>(`/reports/${reportId}/verify`, {
    simulated_tampered_summary: simulatedTamperedSummary,
  });
  return response.data;
};

export const getSystemStatus = async (): Promise<SystemStatusResponse> => {
  const response = await api.get<SystemStatusResponse>('/system/status');
  return response.data;
};

export const getStats = async (): Promise<StatsOverviewResponse> => {
  const response = await api.get<StatsOverviewResponse>('/stats');
  return response.data;
};

export default api;
