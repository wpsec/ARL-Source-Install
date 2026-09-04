import React from 'react';
import { AI_DENOISE_MODULE_IDS } from '../config/modules';

export type HttpMethod = 'GET' | 'POST';

export type JsonValue = Record<string, any>;

export type OpenModuleOptions = {
  resetScroll?: boolean;
};

export type OpenModuleHandler = (moduleId: string, nextFilters?: JsonValue, options?: OpenModuleOptions) => void;

export type ModuleAction = {
  id: string;
  label: string;
  method: HttpMethod;
  path: string;
  description?: string;
  payloadTemplate?: JsonValue;
  selectedField?: string;
  selectionMode?: 'none' | 'single' | 'multiple';
  sendPayloadAsQuery?: boolean;
  download?: boolean;
  reloadAfter?: boolean;
  allowPayloadEdit?: boolean;
  fileFieldName?: string;
  fileAccept?: string;
};

export type ModuleSearchField = {
  key: string;
  label: string;
  placeholder: string;
  inputType?: 'text' | 'number' | 'select';
  options?: Array<{ label: string; value: string }>;
  dynamicOptionsKey?: 'policy_name' | 'task_name' | 'vuln_category';
};

export type ModuleConfig = {
  id: string;
  label: string;
  description: string;
  group: string;
  icon: React.ComponentType<{ className?: string }>;
  hidden?: boolean;
  listPath?: string;
  rowIdKey?: string;
  defaultOrder?: string;
  quickFilterKey?: string;
  columns?: string[];
  sortableColumns?: string[];
  columnLabels?: Record<string, string>;
  searchFields?: ModuleSearchField[];
  showIndex?: boolean;
  exportPath?: string;
  actions?: ModuleAction[];
};

export type ModuleListCacheEntry = {
  rows: any[];
  total: number;
  page: number;
  size: number;
  order: string;
  quickFilter: string;
  searchForm: JsonValue;
  scrollTop?: number;
};

export type LoadRowsOptions = {
  page?: number;
  size?: number;
  order?: string;
  forceRefresh?: boolean;
  filters?: JsonValue;
};

export type ApiRequestOptions = {
  method?: HttpMethod;
  query?: JsonValue;
  body?: JsonValue | FormData;
  download?: boolean;
};

export type TaskReportExportFormat = 'excel' | 'html' | 'ai_markdown';

export type TaskReportExportPhase = 'creating' | 'queued' | 'running' | 'downloading' | 'success' | 'error';

export type TaskReportExportFeedback = {
  phase: TaskReportExportPhase;
  progress: number;
  title: string;
  summary: string;
  detail: string;
  formatLabel: string;
  taskCount: number;
  jobId: string;
  fileName: string;
  error: string;
};

export type SensitiveVerifyContext = 'api' | 'ai';

export type AiDenoiseModuleId = (typeof AI_DENOISE_MODULE_IDS)[number];

export type AiDenoiseResultItem = {
  row_key: string;
  result_level: 'disabled' | 'safe' | 'suspicious' | 'danger';
  risk_level: string;
  trust: string;
  display_text: string;
  summary: string;
  evidence: string[];
  suggestions: string[];
  source: 'disabled' | 'rule' | 'ai';
  prompt_id: string;
  prompt_name?: string;
  note?: string;
  analyzed_at: string;
  cert_expire_at?: string;
  cert_expire_days?: number;
  finger_result?: string[];
  dialogue_records?: Array<{
    role: 'system' | 'user' | 'assistant' | 'tool';
    content: string;
  }>;
};

export type AiDenoiseConfigSnapshot = {
  enable: boolean;
  moduleEnabled: boolean;
  promptId: string;
};

export type FlatPayloadField = {
  path: string;
  value: any;
  depth: number;
};
