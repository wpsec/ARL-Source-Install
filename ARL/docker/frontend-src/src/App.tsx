import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  ChevronsUpDown,
  Cpu,
  Database,
  Download,
  Eye,
  FileCode,
  FlaskConical,
  GitBranch,
  Globe,
  Key,
  LayoutDashboard,
  Link,
  Lock,
  Monitor,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Terminal,
  Upload,
  User,
  Wrench,
  X,
  Zap,
} from 'lucide-react';
import Sidebar from './components/Sidebar';
import { ThemeProvider } from './context/ThemeContext';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

declare const __ARL_VERSION__: string;

type HttpMethod = 'GET' | 'POST';
type JsonValue = Record<string, any>;

type ModuleAction = {
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

type ModuleSearchField = {
  key: string;
  label: string;
  placeholder: string;
  inputType?: 'text' | 'number' | 'select';
  options?: Array<{ label: string; value: string }>;
  dynamicOptionsKey?: 'policy_name';
};

type ModuleConfig = {
  id: string;
  label: string;
  description: string;
  group: string;
  icon: React.ComponentType<{ className?: string }>;
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

type ApiRequestOptions = {
  method?: HttpMethod;
  query?: JsonValue;
  body?: JsonValue | FormData;
  download?: boolean;
};

const API_BASE = '/api';
const TOKEN_KEY = 'arl-token';
const USERNAME_KEY = 'arl-username';
const ACTIVE_MODULE_KEY = 'arl-active-module';
const UNIFIED_SELECT_CLASS =
  'w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm appearance-none pr-9 ' +
  'focus:outline-none focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20 transition';

const modules: ModuleConfig[] = [
  {
    id: 'dashboard',
    label: '我的仪表盘',
    description: '实时总览任务、资产、风险与系统状态',
    group: '核心功能',
    icon: LayoutDashboard,
  },
  {
    id: 'system_monitor',
    label: '系统监控',
    description: '实时查看主机资源、CPU、内存、磁盘与网络趋势',
    group: '核心功能',
    icon: Monitor,
  },
  {
    id: 'task',
    label: '任务管理',
    description: '任务下发、全局查看、同名任务查看、批量停止/删除/导出',
    group: '核心功能',
    icon: Activity,
    listPath: '/task/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    showIndex: false,
    columns: ['name', 'target', 'statistic_summary', 'progress', 'options_summary', 'status', 'start_time', 'end_time', '_id'],
    columnLabels: {
      name: '任务名',
      target: '目标',
      statistic_summary: '统计',
      options_summary: '配置项',
      progress: '扫描进度',
      status: '状态',
      start_time: '开始时间',
      end_time: '结束时间',
      _id: 'Task_Id',
    },
    searchFields: [
      { key: 'name', label: '任务名', placeholder: '请输入任务名进行搜索' },
      { key: 'target', label: '目标', placeholder: '请输入目标进行搜索' },
      { key: '_id', label: 'Task_Id', placeholder: '请输入Task_Id进行搜索' },
      {
        key: 'status',
        label: '状态',
        placeholder: '请选择状态',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '等待中', value: 'waiting' },
          { label: '运行中', value: 'running' },
          { label: '已完成', value: 'done' },
          { label: '已停止', value: 'stop' },
          { label: '异常', value: 'error' },
        ],
      },
      {
        key: 'type',
        label: '任务类型',
        placeholder: '请选择任务类型',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '域名任务', value: 'domain' },
          { label: 'IP任务', value: 'ip' },
          { label: '风险巡航任务', value: 'risk_cruising' },
          { label: 'FOFA任务', value: 'fofa' },
          { label: '添加站点任务', value: 'asset_site_add' },
        ],
      },
    ],
    exportPath: '/export/{task_id}',
    actions: [
      {
        id: 'create_task',
        label: '添加任务',
        method: 'POST',
        path: '/task/',
        payloadTemplate: {
          name: '新扫描任务',
          target: 'example.com',
          domain_brute: true,
          domain_brute_type: 'big',
          domain_dict: '',
          file_leak_dict: '',
          port_scan: true,
          port_scan_type: 'test',
          port_custom: '80,443',
          service_detection: false,
          service_brute: false,
          os_detection: false,
          site_identify: false,
          site_capture: false,
          file_leak: false,
          search_engines: false,
          site_spider: false,
          arl_search: false,
          alt_dns: false,
          ssl_cert: false,
          dns_query_plugin: false,
          skip_scan_cdn_ip: false,
          nuclei_scan: false,
          findvhost: false,
          web_info_hunter: false,
          dingding_notify: false,
        },
      },
      {
        id: 'fofa_submit',
        label: 'FOFA任务下发',
        method: 'POST',
        path: '/task_fofa/submit',
        payloadTemplate: {
          query: 'domain="example.com"',
          name: 'FOFA任务',
          policy_id: '',
        },
      },
      {
        id: 'task_stop_batch',
        label: '批量停止',
        method: 'POST',
        path: '/task/batch_stop/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
      },
      {
        id: 'task_restart_batch',
        label: '重启所选',
        method: 'POST',
        path: '/task/restart/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
      },
      {
        id: 'task_delete_batch',
        label: '批量删除',
        method: 'POST',
        path: '/task/delete/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
          del_task_data: false,
        },
      },
      {
        id: 'task_policy_submit',
        label: '策略下发',
        method: 'POST',
        path: '/task/policy/',
        payloadTemplate: {
          name: '策略任务',
          task_tag: 'task',
          target: 'example.com',
          policy_id: '',
          result_set_id: '',
        },
      },
      {
        id: 'task_sync',
        label: '同步资产组',
        method: 'POST',
        path: '/task/sync/',
        payloadTemplate: {
          task_id: '',
          scope_id: '',
        },
      },
      {
        id: 'task_sync_scope_lookup',
        label: '匹配资产组',
        method: 'GET',
        path: '/task/sync_scope/',
        payloadTemplate: {
          target: 'www.example.com',
        },
        sendPayloadAsQuery: true,
      },
      {
        id: 'task_batch_export_site',
        label: '站点批量导出',
        method: 'POST',
        path: '/batch_export/site/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_export_domain',
        label: '域名批量导出',
        method: 'POST',
        path: '/batch_export/domain/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_export_ip',
        label: 'IP批量导出',
        method: 'POST',
        path: '/batch_export/ip/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_export_url',
        label: 'URL批量导出',
        method: 'POST',
        path: '/batch_export/url/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_export_fileleak',
        label: '文件泄露批量导出',
        method: 'POST',
        path: '/batch_export/fileleak/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_export_port',
        label: 'IP端口批量导出',
        method: 'POST',
        path: '/batch_export/ip_port/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_export_cip',
        label: 'C段批量导出',
        method: 'POST',
        path: '/batch_export/cip/',
        selectedField: 'task_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_id: [],
        },
        download: true,
      },
      {
        id: 'task_batch_excel_report',
        label: '报告导出',
        method: 'POST',
        path: '/export/batch',
        selectedField: 'task_ids',
        selectionMode: 'multiple',
        payloadTemplate: {
          task_ids: [],
        },
        download: true,
      },
      {
        id: 'task_download_single_report',
        label: '下载单任务报告',
        method: 'GET',
        path: '/export/{task_id}',
        selectedField: 'task_id',
        selectionMode: 'single',
        payloadTemplate: {
          task_id: '',
        },
        download: true,
      },
    ],
  },
  {
    id: 'task_schedule',
    label: '计划任务',
    description: 'future_scan / recurrent_scan 计划调度',
    group: '核心功能',
    icon: Settings,
    listPath: '/task_schedule/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    showIndex: true,
    columns: ['name', 'target', 'schedule_type', 'status', 'policy_name', 'time_config', 'last_run_date', 'next_run_date', 'run_number'],
    columnLabels: {
      name: '任务名',
      target: '目标',
      schedule_type: '类型',
      status: '状态',
      policy_name: '策略',
      time_config: '时间配置',
      last_run_date: '上次运行时间',
      next_run_date: '下次运行时间',
      run_number: '运行次数',
    },
    searchFields: [
      { key: 'name', label: '任务名称', placeholder: '请输入任务名称进行搜索' },
      { key: 'target', label: '目标', placeholder: '请输入目标进行搜索' },
      {
        key: 'policy_name',
        label: '策略名称',
        placeholder: '请选择策略名称',
        inputType: 'select',
        dynamicOptionsKey: 'policy_name',
      },
      {
        key: 'schedule_type',
        label: '计划类型',
        placeholder: '请选择计划类型',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '定时下发', value: 'future_scan' },
          { label: '周期下发', value: 'recurrent_scan' },
        ],
      },
      {
        key: 'schedule_status',
        label: '状态',
        placeholder: '请选择状态',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '待调度', value: 'scheduled' },
          { label: '已停止', value: 'stop' },
          { label: '已完成', value: 'done' },
          { label: '异常', value: 'error' },
        ],
      },
    ],
    actions: [
      {
        id: 'task_schedule_add',
        label: '添加计划任务',
        method: 'POST',
        path: '/task_schedule/',
        payloadTemplate: {
          name: '计划任务',
          target: 'example.com',
          schedule_type: 'future_scan',
          policy_id: '',
          cron: '0 2 * * *',
          start_date: '',
          task_tag: 'task',
          notify_enable: true,
          notify_kb_enable: false,
          notify_channel: 'dingding',
          notify_on: 'finished',
        },
      },
      {
        id: 'task_schedule_stop',
        label: '批量停止',
        method: 'POST',
        path: '/task_schedule/stop/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'task_schedule_recover',
        label: '批量恢复',
        method: 'POST',
        path: '/task_schedule/recover/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'task_schedule_delete',
        label: '批量删除',
        method: 'POST',
        path: '/task_schedule/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'scheduler',
    label: '资产监控',
    description: '资产监控任务查询与批量启停管理',
    group: '核心功能',
    icon: Monitor,
    listPath: '/scheduler/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    showIndex: true,
    columns: ['name', 'domain', 'scope_id', 'interval', 'last_run_date', 'next_run_date', 'run_number'],
    sortableColumns: ['domain', 'run_number'],
    columnLabels: {
      name: '名称',
      domain: '域名',
      scope_id: '资产组范围ID',
      interval: '运行间隔',
      last_run_date: '上一次运行日期',
      next_run_date: '下一次运行日期',
      run_number: '运行次数',
    },
    searchFields: [
      { key: 'name', label: '名称', placeholder: '请输入名称进行搜索' },
      { key: 'domain', label: '域名', placeholder: '请输入域名进行搜索' },
      { key: 'scope_id', label: '资产范围ID', placeholder: '请输入资产范围ID进行搜索' },
    ],
    actions: [
      {
        id: 'scheduler_delete',
        label: '批量删除',
        method: 'POST',
        path: '/scheduler/delete/',
        selectedField: 'job_id',
        selectionMode: 'multiple',
        payloadTemplate: { job_id: [] },
      },
      {
        id: 'scheduler_stop',
        label: '批量停止',
        method: 'POST',
        path: '/scheduler/stop/batch',
        selectedField: 'job_id',
        selectionMode: 'multiple',
        payloadTemplate: { job_id: [] },
      },
      {
        id: 'scheduler_recover',
        label: '批量恢复',
        method: 'POST',
        path: '/scheduler/recover/batch',
        selectedField: 'job_id',
        selectionMode: 'multiple',
        payloadTemplate: { job_id: [] },
      },
    ],
  },
  {
    id: 'policy',
    label: '策略配置',
    description: '策略增删改查及任务选项模板',
    group: '核心功能',
    icon: Wrench,
    listPath: '/policy/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    showIndex: true,
    columns: ['name', 'desc', 'update_date'],
    columnLabels: {
      name: '名称',
      desc: '描述',
      update_date: '更新时间',
    },
    searchFields: [{ key: 'name', label: '策略名称', placeholder: '请输入策略名称进行搜索' }],
    actions: [
      {
        id: 'policy_add',
        label: '新增策略',
        method: 'POST',
        path: '/policy/add/',
        payloadTemplate: {
          name: '默认策略',
          desc: '自动化创建',
          policy: {
            domain_config: {
              domain_brute: true,
              domain_brute_type: 'big',
              alt_dns: false,
              arl_search: false,
              dns_query_plugin: false,
            },
            ip_config: {
              port_scan: true,
              port_scan_type: 'test',
              service_detection: false,
              os_detection: false,
              ssl_cert: false,
              skip_scan_cdn_ip: true,
              port_custom: '80,443',
              host_timeout_type: 'default',
              host_timeout: 900,
              port_parallelism: 32,
              port_min_rate: 60,
            },
            site_config: {
              site_identify: false,
              site_capture: false,
              search_engines: false,
              site_spider: false,
              nuclei_scan: false,
              web_info_hunter: false,
            },
            domain_dict: '',
            file_leak_dict: '',
            file_leak: false,
            npoc_service_detection: false,
            poc_config: [],
            brute_config: [],
            scope_config: {
              scope_id: '',
            },
          },
        },
      },
      {
        id: 'policy_edit',
        label: '更新策略',
        method: 'POST',
        path: '/policy/edit/',
        payloadTemplate: {
          policy_id: '',
          policy_data: {
            name: '更新后的策略名',
          },
        },
      },
      {
        id: 'policy_delete',
        label: '删除所选',
        method: 'POST',
        path: '/policy/delete/',
        selectedField: 'policy_id',
        selectionMode: 'multiple',
        payloadTemplate: { policy_id: [] },
      },
    ],
  },
  {
    id: 'asset_scope',
    label: '资产分组',
    description: '资产分组查询与维护',
    group: '核心功能',
    icon: Shield,
    listPath: '/asset_scope/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    exportPath: '/asset_scope/export/',
    columns: ['name', 'scope', '_id'],
    sortableColumns: ['name'],
    columnLabels: {
      name: '资产组名称',
      scope: '资产范围',
      _id: '资产范围ID',
    },
    searchFields: [
      { key: 'name', label: '资产组名称', placeholder: '请输入资产组名称进行搜索' },
      { key: 'scope', label: '资产范围', placeholder: '请输入资产范围进行搜索' },
      { key: '_id', label: '资产范围ID', placeholder: '请输入资产范围ID进行搜索' },
    ],
    actions: [
      {
        id: 'asset_scope_add',
        label: '新建资产分组',
        method: 'POST',
        path: '/asset_scope/',
        payloadTemplate: {
          name: '新资产组',
          scope: 'example.com',
          scope_type: 'domain',
        },
      },
      {
        id: 'asset_scope_delete',
        label: '批量删除',
        method: 'POST',
        path: '/asset_scope/delete/',
        selectedField: 'scope_id',
        selectionMode: 'multiple',
        payloadTemplate: { scope_id: [] },
      },
      {
        id: 'asset_scope_add_scope',
        label: '添加资产分组范围',
        method: 'POST',
        path: '/asset_scope/add/',
        payloadTemplate: {
          scope_id: '',
          scope: 'example.com',
        },
      },
      {
        id: 'asset_scope_add_scheduler',
        label: '添加监控任务',
        method: 'POST',
        path: '/scheduler/add/',
        payloadTemplate: {
          scope_id: '',
          domain: 'example.com',
          interval: 86400,
          name: '资产监控任务',
          policy_id: '',
        },
      },
      {
        id: 'asset_scope_add_site_monitor',
        label: '添加站点监控任务',
        method: 'POST',
        path: '/scheduler/add/site_monitor/',
        payloadTemplate: {
          scope_id: '',
          interval: 86400,
          name: '站点监控任务',
        },
      },
      {
        id: 'asset_scope_add_wih_monitor',
        label: '添加WIH监控任务',
        method: 'POST',
        path: '/scheduler/add/wih_monitor/',
        payloadTemplate: {
          scope_id: '',
          interval: 86400,
          name: 'WIH监控任务',
        },
      },
    ],
  },
  {
    id: 'asset_domain',
    label: '资产域名',
    description: '资产组内域名资产',
    group: '资产数据',
    icon: Globe,
    listPath: '/asset_domain/',
    rowIdKey: '_id',
    quickFilterKey: 'domain',
    showIndex: true,
    columns: ['domain', 'type', 'record', 'ips', 'source'],
    columnLabels: {
      domain: '域名',
      type: '解析类型',
      record: '记录值',
      ips: '关联IP',
      source: '来源',
    },
    searchFields: [
      { key: 'domain', label: '域名', placeholder: '请输入域名进行搜索' },
      { key: 'record', label: '记录值', placeholder: '请输入记录值进行搜索' },
      { key: 'type', label: '类型', placeholder: '请输入类型进行搜索' },
      { key: 'ips', label: 'IP', placeholder: '请输入IP进行搜索' },
      { key: 'source', label: '来源', placeholder: '请输入来源进行搜索' },
    ],
    exportPath: '/asset_domain/export/',
    actions: [
      {
        id: 'asset_domain_delete',
        label: '删除所选',
        method: 'POST',
        path: '/asset_domain/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'asset_site',
    label: '资产站点',
    description: '资产组内站点资产',
    group: '资产数据',
    icon: Link,
    listPath: '/asset_site/',
    rowIdKey: '_id',
    quickFilterKey: 'site',
    showIndex: true,
    columns: ['site', 'title', 'headers', 'finger'],
    columnLabels: {
      site: '站点',
      title: '标题',
      headers: 'headers',
      finger: 'finger',
    },
    searchFields: [
      { key: 'site', label: '站点', placeholder: '请输入站点进行搜索' },
      { key: 'hostname', label: '主机名', placeholder: '请输入主机名进行搜索' },
      { key: 'title', label: '标题', placeholder: '请输入标题进行搜索' },
      { key: 'http_server', label: 'Web Server', placeholder: '请输入Web Server进行搜索' },
      { key: 'status', label: '状态码', placeholder: '请输入状态码进行搜索', inputType: 'number' },
      { key: 'headers', label: '标头', placeholder: '请输入标头进行搜索' },
      { key: 'finger.name', label: '指 纹', placeholder: '请输入指 纹进行搜索' },
      { key: 'favicon.hash', label: 'favicon hash', placeholder: '请输入favicon hash进行搜索', inputType: 'number' },
      { key: 'tag', label: '标签', placeholder: '请输入标签进行搜索' },
    ],
    exportPath: '/asset_site/export/',
    actions: [
      {
        id: 'asset_site_delete',
        label: '删除所选',
        method: 'POST',
        path: '/asset_site/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'asset_site_save_result_set',
        label: '保存结果集',
        method: 'GET',
        path: '/asset_site/save_result_set/',
        sendPayloadAsQuery: true,
        payloadTemplate: {
          scope_id: '',
          page: 1,
          size: 50,
        },
      },
    ],
  },
  {
    id: 'asset_ip',
    label: '资产IP',
    description: '资产组内IP资产',
    group: '资产数据',
    icon: Network,
    listPath: '/asset_ip/',
    rowIdKey: '_id',
    quickFilterKey: 'ip',
    showIndex: true,
    columns: ['ip', 'os_info.name', 'port_info.port_id', 'domain', 'cdn_name'],
    columnLabels: {
      ip: 'IP',
      'os_info.name': '操作系统',
      'port_info.port_id': '开放端口',
      domain: '关联域名',
      cdn_name: 'CDN',
    },
    searchFields: [
      { key: 'ip', label: 'IP', placeholder: '请输入IP进行搜索' },
      { key: 'port_info.port_id', label: '端口', placeholder: '请输入端口进行搜索', inputType: 'number' },
      { key: 'os_info.name', label: '操作系统', placeholder: '请输入操作系统进行搜索' },
      { key: 'domain', label: '域名', placeholder: '请输入域名进行搜索' },
      { key: 'cdn_name', label: 'CDN', placeholder: '请输入CDN进行搜索' },
    ],
    exportPath: '/asset_ip/export/',
    actions: [
      {
        id: 'asset_ip_delete',
        label: '删除所选',
        method: 'POST',
        path: '/asset_ip/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'asset_wih',
    label: '资产WIH',
    description: '资产组内 JS 信息猎取数据',
    group: '资产数据',
    icon: FileCode,
    listPath: '/asset_wih/',
    rowIdKey: '_id',
    quickFilterKey: 'content',
    exportPath: '/asset_wih/export/',
  },
  {
    id: 'site',
    label: '站点',
    description: '任务扫描站点数据',
    group: '资产数据',
    icon: Globe,
    listPath: '/site/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'site',
    columns: ['site', 'title', 'headers', 'finger', 'screenshot'],
    columnLabels: {
      site: '站点',
      title: '标题',
      headers: 'headers',
      finger: 'finger',
      screenshot: '截图',
    },
    searchFields: [
      { key: 'site', label: '站点', placeholder: '请输入站点进行搜索' },
      { key: 'hostname', label: '主机名', placeholder: '请输入主机名进行搜索' },
      { key: 'title', label: '标题', placeholder: '请输入标题进行搜索' },
      { key: 'http_server', label: 'Web Server', placeholder: '请输入Web Server进行搜索' },
      { key: 'status', label: '状态码', placeholder: '请输入状态码进行搜索', inputType: 'number' },
      { key: 'headers', label: '标头', placeholder: '请输入标头进行搜索' },
      { key: 'finger.name', label: '指 纹', placeholder: '请输入指 纹进行搜索' },
      { key: 'favicon.hash', label: 'favicon hash', placeholder: '请输入favicon hash进行搜索', inputType: 'number' },
      { key: 'tag', label: '标签', placeholder: '请输入标签进行搜索' },
    ],
    exportPath: '/site/export/',
    actions: [
      {
        id: 'site_delete',
        label: '删除所选',
        method: 'POST',
        path: '/site/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: {
          _id: [],
        },
      },
      {
        id: 'site_save_result_set',
        label: '保存结果集',
        method: 'GET',
        path: '/site/save_result_set/',
        sendPayloadAsQuery: true,
        payloadTemplate: {
          page: 1,
          size: 50,
        },
      },
    ],
  },
  {
    id: 'domain',
    label: '子域名',
    description: '任务扫描域名数据',
    group: '资产数据',
    icon: Globe,
    listPath: '/domain/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'domain',
    columns: ['domain', 'type', 'record', 'ips', 'source'],
    columnLabels: {
      domain: '域名',
      type: '解析类型',
      record: '记录值',
      ips: '关联IP',
      source: '来源',
    },
    searchFields: [
      { key: 'domain', label: '域名', placeholder: '请输入域名进行搜索' },
      { key: 'record', label: '记录值', placeholder: '请输入记录值进行搜索' },
      { key: 'type', label: '类型', placeholder: '请输入类型进行搜索' },
      { key: 'ips', label: 'IP', placeholder: '请输入IP进行搜索' },
      { key: 'source', label: '来源', placeholder: '请输入来源进行搜索' },
    ],
    exportPath: '/domain/export/',
    actions: [
      {
        id: 'domain_delete',
        label: '删除所选',
        method: 'POST',
        path: '/domain/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'ip',
    label: 'IP',
    description: '任务扫描IP和端口数据',
    group: '资产数据',
    icon: Network,
    listPath: '/ip/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'ip',
    columns: ['ip', 'os_info.name', 'port_info.port_id', 'domain', 'cdn_name', 'geo_summary', 'asn_summary'],
    columnLabels: {
      ip: 'IP',
      'os_info.name': '操作系统',
      'port_info.port_id': '开放端口',
      domain: '关联域名',
      cdn_name: 'CDN',
      geo_summary: 'Geo',
      asn_summary: 'AS',
    },
    searchFields: [
      { key: 'ip', label: 'IP', placeholder: '请输入IP进行搜索' },
      { key: 'port_info.port_id', label: '端口', placeholder: '请输入端口进行搜索', inputType: 'number' },
      { key: 'os_info.name', label: '操作系统', placeholder: '请输入操作系统进行搜索' },
      { key: 'domain', label: '域名', placeholder: '请输入域名进行搜索' },
      { key: 'cdn_name', label: 'CDN', placeholder: '请输入CDN进行搜索' },
      {
        key: 'ip_type',
        label: 'IP类别',
        placeholder: '请选择IP类别',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '内网', value: 'PRIVATE' },
          { label: '公网', value: 'PUBLIC' },
        ],
      },
    ],
    exportPath: '/ip/export/',
    actions: [
      {
        id: 'ip_export_ip',
        label: '导出纯IP',
        method: 'GET',
        path: '/ip/export_ip/',
        download: true,
      },
      {
        id: 'ip_export_domain',
        label: '导出域名',
        method: 'GET',
        path: '/ip/export_domain/',
        download: true,
      },
      {
        id: 'ip_delete',
        label: '删除所选',
        method: 'POST',
        path: '/ip/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'url',
    label: 'URL信息',
    description: '任务URL结果',
    group: '资产数据',
    icon: Link,
    listPath: '/url/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'url',
    columns: ['url', 'title', 'status_code', 'content_length', 'source'],
    columnLabels: {
      url: 'URL',
      title: '标题',
      status_code: '状态码',
      content_length: 'body 长度',
      source: '来源',
    },
    searchFields: [
      { key: 'url', label: 'URL', placeholder: '请输入URL进行搜索' },
      { key: 'title', label: '标题', placeholder: '请输入标题进行搜索' },
      { key: 'status_code', label: '状态码', placeholder: '请输入状态码进行搜索', inputType: 'number' },
      { key: 'content_length', label: 'body 长度', placeholder: '请输入body 长度进行搜索', inputType: 'number' },
      { key: 'source', label: '来源', placeholder: '请输入来源进行搜索' },
    ],
    exportPath: '/url/export/',
  },
  {
    id: 'cert',
    label: 'SSL证书',
    description: 'TLS证书资产',
    group: '资产数据',
    icon: Shield,
    listPath: '/cert/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'ip',
    columns: ['host', 'cert_summary'],
    columnLabels: {
      host: 'HOST',
      cert_summary: 'CERT',
    },
    searchFields: [
      { key: 'ip', label: 'IP字段', placeholder: '请输入IP字段进行搜索' },
      { key: 'cert.issuer_dn', label: '签发者名称', placeholder: '请输入签发者名称进行搜索' },
      { key: 'cert.subject_dn', label: '主题名称', placeholder: '请输入主题名称进行搜索' },
      { key: 'cert.fingerprint.sha1', label: 'SHA-1', placeholder: '请输入SHA-1进行搜索' },
      {
        key: 'cert.extensions.subjectAltName',
        label: '使用者备用名称',
        placeholder: '请输入使用者备用名称进行搜索',
      },
    ],
    actions: [
      {
        id: 'cert_delete',
        label: '删除所选',
        method: 'POST',
        path: '/cert/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'service',
    label: '服务',
    description: '端口服务识别结果',
    group: '资产数据',
    icon: Server,
    listPath: '/service/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'service_name',
    columns: ['service_name', 'ip_port', 'service_info.product'],
    columnLabels: {
      service_name: '服务',
      ip_port: 'IP端口',
      'service_info.product': 'Product',
    },
    searchFields: [
      { key: 'service_name', label: '服务', placeholder: '请输入服务进行搜索' },
      { key: 'service_info.ip', label: 'IP', placeholder: '请输入IP进行搜索' },
      { key: 'service_info.port_id', label: '端口', placeholder: '请输入端口进行搜索', inputType: 'number' },
      { key: 'service_info.product', label: '产品', placeholder: '请输入产品进行搜索' },
    ],
  },
  {
    id: 'npoc_service',
    label: 'C段',
    description: '协议探测与目标结果',
    group: '资产数据',
    icon: Terminal,
    listPath: '/npoc_service/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'target',
    columns: ['scheme', 'host', 'port', 'target'],
    columnLabels: {
      scheme: '协议',
      host: '主机',
      port: '端口',
      target: '目标',
    },
    searchFields: [
      { key: 'scheme', label: '协议', placeholder: '请输入协议进行搜索' },
      { key: 'host', label: '主机', placeholder: '请输入主机进行搜索' },
      { key: 'port', label: '端口', placeholder: '请输入端口进行搜索' },
      { key: 'target', label: '目标', placeholder: '请输入目标进行搜索' },
    ],
  },
  {
    id: 'cip',
    label: 'C段',
    description: 'C段分布统计',
    group: '资产数据',
    icon: Database,
    listPath: '/cip/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'cidr_ip',
    defaultOrder: '-ip_count',
    columns: ['cidr_ip', 'ip_count', 'domain_count'],
    sortableColumns: ['cidr_ip', 'ip_count', 'domain_count'],
    columnLabels: {
      cidr_ip: 'C段',
      ip_count: 'IP数',
      domain_count: '域名数',
    },
    searchFields: [
      { key: 'cidr_ip', label: 'C段', placeholder: '请输入C段进行搜索' },
    ],
    exportPath: '/cip/export/',
  },
  {
    id: 'stat_finger',
    label: '指纹统计',
    description: '识别指纹统计',
    group: '资产数据',
    icon: Activity,
    listPath: '/stat_finger/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'name',
    columns: ['name', 'cnt'],
    columnLabels: {
      name: 'finger',
      cnt: '数量',
    },
    searchFields: [
      { key: 'name', label: 'finger', placeholder: '请输入finger进行搜索' },
    ],
  },
  {
    id: 'vuln',
    label: '风险',
    description: '风险结果查询和处置',
    group: '风险与规则',
    icon: AlertTriangle,
    listPath: '/vuln/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'vul_name',
    columns: ['vul_name', 'plg_type', 'app_name', 'target', 'credential', 'save_date'],
    columnLabels: {
      vul_name: '风险名称',
      plg_type: '类别',
      app_name: '应用名',
      target: '目标',
      credential: '凭证',
      save_date: '发现时间',
    },
    searchFields: [
      { key: 'vul_name', label: '风险名称', placeholder: '请输入风险名称进行搜索' },
      { key: 'plg_type', label: '类别', placeholder: '请输入类别进行搜索' },
      { key: 'app_name', label: '应用名', placeholder: '请输入应用名进行搜索' },
      { key: 'target', label: '目标', placeholder: '请输入目标进行搜索' },
    ],
    actions: [
      {
        id: 'vuln_delete',
        label: '删除所选',
        method: 'POST',
        path: '/vuln/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'nuclei_result',
    label: 'nuclei',
    description: 'Nuclei 模板扫描结果',
    group: '风险与规则',
    icon: FlaskConical,
    listPath: '/nuclei_result/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'vuln_name',
    columns: ['template_id', 'target', 'vuln_url', 'vuln_name', 'vuln_severity', 'save_date', 'curl_command'],
    columnLabels: {
      template_id: '模板ID',
      target: '目标',
      vuln_url: '风险URL',
      vuln_name: '风险名称',
      vuln_severity: '风险等级',
      save_date: '保存时间',
      curl_command: '验证命令',
    },
    searchFields: [
      { key: 'template_id', label: '模版ID', placeholder: '请输入模版ID进行搜索' },
      { key: 'target', label: '目标', placeholder: '请输入目标进行搜索' },
      { key: 'vuln_url', label: '风险URL', placeholder: '请输入风险URL进行搜索' },
      { key: 'vuln_name', label: '风险名称', placeholder: '请输入风险名称进行搜索' },
    ],
    actions: [
      {
        id: 'nuclei_result_delete',
        label: '删除所选',
        method: 'POST',
        path: '/nuclei_result/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'fileleak',
    label: '文件泄露',
    description: '敏感文件泄露结果',
    group: '风险与规则',
    icon: ShieldAlert,
    listPath: '/fileleak/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'url',
    columns: ['url', 'title', 'status_code', 'content_length'],
    columnLabels: {
      url: 'URL',
      title: '标题',
      status_code: '状态码',
      content_length: 'body 长度',
    },
    searchFields: [
      { key: 'url', label: 'URL', placeholder: '请输入URL进行搜索' },
      { key: 'title', label: '标题', placeholder: '请输入标题进行搜索' },
      { key: 'status_code', label: '状态码', placeholder: '请输入状态码进行搜索', inputType: 'number' },
      { key: 'content_length', label: 'body 长度', placeholder: '请输入body 长度进行搜索', inputType: 'number' },
    ],
    actions: [
      {
        id: 'fileleak_delete',
        label: '删除所选',
        method: 'POST',
        path: '/fileleak/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
    exportPath: '/fileleak/export/',
  },
  {
    id: 'wih',
    label: 'WIH',
    description: '任务中提取的JS信息',
    group: '风险与规则',
    icon: FileCode,
    listPath: '/wih/',
    rowIdKey: '_id',
    showIndex: true,
    quickFilterKey: 'content',
    columns: ['record_type', 'content', 'source', 'site'],
    columnLabels: {
      record_type: '记录类型',
      content: '内容',
      source: '来源 JS',
      site: '来源站点',
    },
    searchFields: [
      { key: 'record_type', label: '记录类型', placeholder: '请输入记录类型进行搜索' },
      { key: 'content', label: '内容', placeholder: '请输入内容进行搜索' },
      { key: 'source', label: '来源 JS', placeholder: '请输入来源 JS进行搜索' },
      { key: 'site', label: '来源站点', placeholder: '请输入来源站点进行搜索' },
    ],
    exportPath: '/wih/export/',
  },
  {
    id: 'poc',
    label: 'PoC管理',
    description: 'PoC / brute 插件管理',
    group: '风险与规则',
    icon: Shield,
    listPath: '/poc/',
    rowIdKey: '_id',
    quickFilterKey: 'plugin_name',
    showIndex: true,
    columns: ['plugin_name', 'plugin_type', 'category', 'app_name', 'vul_name', 'scheme', 'update_date'],
    columnLabels: {
      plugin_name: '插件名称',
      plugin_type: '类型',
      category: '分类',
      app_name: '应用',
      vul_name: '风险名称',
      scheme: '协议',
      update_date: '更新时间',
    },
    actions: [
      {
        id: 'poc_sync',
        label: '同步PoC',
        method: 'GET',
        path: '/poc/sync/',
      },
      {
        id: 'poc_clear',
        label: '清空PoC库',
        method: 'GET',
        path: '/poc/delete/',
      },
    ],
  },
  {
    id: 'fingerprint',
    label: '指纹规则',
    description: 'Web 指纹规则管理',
    group: '风险与规则',
    icon: FileCode,
    listPath: '/fingerprint/',
    rowIdKey: '_id',
    quickFilterKey: 'name',
    showIndex: true,
    columns: ['name', 'human_rule', 'update_date'],
    columnLabels: {
      name: '名称',
      human_rule: '规则',
      update_date: '更新时间',
    },
    actions: [
      {
        id: 'fingerprint_add',
        label: '新增指纹',
        method: 'POST',
        path: '/fingerprint/',
        payloadTemplate: {
          name: '自定义指纹',
          human_rule: 'header="Server: nginx"',
        },
      },
      {
        id: 'fingerprint_delete',
        label: '删除所选',
        method: 'POST',
        path: '/fingerprint/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'fingerprint_export',
        label: '导出规则',
        method: 'GET',
        path: '/fingerprint/export/',
        download: true,
      },
      {
        id: 'fingerprint_upload',
        label: '上传规则文件',
        method: 'POST',
        path: '/fingerprint/upload/',
        fileFieldName: 'file',
        fileAccept: '.yml,.yaml',
        allowPayloadEdit: false,
      },
    ],
  },
  {
    id: 'github_task',
    label: 'GitHub任务',
    description: 'GitHub 一次性检索任务',
    group: 'GitHub监控',
    icon: GitBranch,
    listPath: '/github_task/',
    rowIdKey: '_id',
    quickFilterKey: 'name',
    columns: ['name', 'keyword', 'result_count', 'status', 'start_time', 'end_time', '_id'],
    columnLabels: {
      name: '任务名',
      keyword: '关键字',
      result_count: '结果数目',
      status: '状态',
      start_time: '开始时间',
      end_time: '结束时间',
      _id: '任务id',
    },
    searchFields: [
      { key: 'name', label: '任务名称', placeholder: '请输入任务名称进行搜索' },
      { key: 'keyword', label: '关键字', placeholder: '请输入关键字进行搜索' },
      {
        key: 'status',
        label: '状态',
        placeholder: '请选择状态',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '等待中', value: 'waiting' },
          { label: '运行中', value: 'running' },
          { label: '已完成', value: 'done' },
          { label: '已停止', value: 'stop' },
          { label: '异常', value: 'error' },
        ],
      },
    ],
    actions: [
      {
        id: 'github_task_add',
        label: '新增GitHub任务',
        method: 'POST',
        path: '/github_task/',
        payloadTemplate: {
          name: 'GitHub泄露检索',
          keyword: 'AKIA',
        },
      },
      {
        id: 'github_task_stop',
        label: '停止所选',
        method: 'POST',
        path: '/github_task/stop/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'github_task_delete',
        label: '删除所选',
        method: 'POST',
        path: '/github_task/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'github_result',
    label: 'GitHub结果',
    description: 'GitHub 泄露检索结果',
    group: 'GitHub监控',
    icon: Search,
    listPath: '/github_result/',
    rowIdKey: '_id',
    quickFilterKey: 'human_content',
    columns: ['repo_full_name', 'path', 'human_content', 'commit_date', 'keyword'],
    columnLabels: {
      repo_full_name: '仓库名',
      path: '路径',
      human_content: '内容',
      commit_date: '提交时间',
      keyword: '关键字',
    },
    searchFields: [
      { key: 'path', label: '路径名', placeholder: '请输入路径名进行搜索' },
      { key: 'repo_full_name', label: '仓库名', placeholder: '请输入仓库名进行搜索' },
      { key: 'human_content', label: '内容', placeholder: '请输入内容进行搜索' },
    ],
  },
  {
    id: 'github_scheduler',
    label: 'GitHub监控',
    description: 'GitHub 定时监控任务',
    group: 'GitHub监控',
    icon: RefreshCw,
    listPath: '/github_scheduler/',
    rowIdKey: '_id',
    quickFilterKey: 'name',
    columns: ['name', 'keyword', 'cron', 'status', 'run_number', 'last_run_date', 'next_run_date'],
    columnLabels: {
      name: '任务名',
      keyword: '关键字',
      cron: 'cron表达式',
      status: '状态',
      run_number: '运行次数',
      last_run_date: '上次运行时间',
      next_run_date: '下次运行时间',
    },
    searchFields: [
      { key: 'name', label: '任务名称', placeholder: '请输入任务名称进行搜索' },
      { key: 'keyword', label: '关键字', placeholder: '请输入关键字进行搜索' },
      {
        key: 'status',
        label: '状态',
        placeholder: '请选择状态',
        inputType: 'select',
        options: [
          { label: '全部', value: '' },
          { label: '运行中', value: 'running' },
          { label: '停止', value: 'stop' },
        ],
      },
    ],
    actions: [
      {
        id: 'github_scheduler_add',
        label: '添加任务',
        method: 'POST',
        path: '/github_scheduler/',
        payloadTemplate: {
          name: 'GitHub监控任务',
          keyword: 'AKIA',
          cron: '0 */6 * * *',
          dingding_notify: true,
          kb_notify_enable: false,
        },
      },
      {
        id: 'github_scheduler_update',
        label: '更新监控任务',
        method: 'POST',
        path: '/github_scheduler/update/',
        payloadTemplate: {
          _id: '',
          name: 'GitHub监控更新',
          keyword: 'sk_live_',
          cron: '0 */6 * * *',
          dingding_notify: true,
          kb_notify_enable: false,
        },
      },
      {
        id: 'github_scheduler_stop',
        label: '停止所选',
        method: 'POST',
        path: '/github_scheduler/stop/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'github_scheduler_recover',
        label: '恢复所选',
        method: 'POST',
        path: '/github_scheduler/recover/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'github_scheduler_delete',
        label: '删除所选',
        method: 'POST',
        path: '/github_scheduler/delete/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
    ],
  },
  {
    id: 'github_monitor_result',
    label: 'GitHub监控结果',
    description: 'GitHub 定时任务结果',
    group: 'GitHub监控',
    icon: Search,
    listPath: '/github_monitor_result/',
    rowIdKey: '_id',
    quickFilterKey: 'human_content',
    columns: ['repo_full_name', 'path', 'human_content', 'commit_date', 'keyword'],
    columnLabels: {
      repo_full_name: '仓库名',
      path: '路径',
      human_content: '内容',
      commit_date: '提交时间',
      keyword: '关键字',
    },
    searchFields: [
      { key: 'path', label: '路径名', placeholder: '请输入路径名进行搜索' },
      { key: 'repo_full_name', label: '仓库名', placeholder: '请输入仓库名进行搜索' },
      { key: 'human_content', label: '内容', placeholder: '请输入内容进行搜索' },
    ],
  },
  {
    id: 'task_fofa',
    label: 'FOFA管理',
    description: 'FOFA 语法测试与任务下发',
    group: '系统集成',
    icon: Search,
    actions: [
      {
        id: 'fofa_test',
        label: '测试FOFA语法',
        method: 'POST',
        path: '/task_fofa/test',
        payloadTemplate: {
          query: 'domain="example.com"',
        },
      },
      {
        id: 'fofa_submit_center',
        label: '提交FOFA任务',
        method: 'POST',
        path: '/task_fofa/submit',
        payloadTemplate: {
          query: 'domain="example.com"',
          name: 'FOFA批量任务',
          policy_id: '',
        },
      },
    ],
  },
  {
    id: 'dingtalk_api',
    label: '钉钉集成',
    description: '钉钉 OpenAPI 调试与知识库联动',
    group: '系统集成',
    icon: Settings,
    actions: [
      {
        id: 'dingtalk_config',
        label: '读取配置状态',
        method: 'GET',
        path: '/dingtalk_api/config/',
      },
      {
        id: 'dingtalk_test',
        label: '测试连通性',
        method: 'POST',
        path: '/dingtalk_api/test/',
        payloadTemplate: {
          force_refresh_token: false,
        },
      },
      {
        id: 'dingtalk_workspaces',
        label: '获取空间列表',
        method: 'POST',
        path: '/dingtalk_api/workspaces/',
        payloadTemplate: {
          operator_id: '',
        },
      },
      {
        id: 'dingtalk_nodes',
        label: '获取节点列表',
        method: 'POST',
        path: '/dingtalk_api/nodes/',
        payloadTemplate: {
          operator_id: '',
          parent_node_id: '',
        },
      },
      {
        id: 'dingtalk_create_workbook',
        label: '创建知识库表格',
        method: 'POST',
        path: '/dingtalk_api/create_workbook/',
        payloadTemplate: {
          title: 'ARL安全报告',
          operator_id: '',
          workspace_id: '',
          parent_node_id: '',
        },
      },
      {
        id: 'dingtalk_sheets',
        label: '获取工作表',
        method: 'POST',
        path: '/dingtalk_api/sheets/',
        payloadTemplate: {
          workbook_id: '',
          operator_id: '',
        },
      },
      {
        id: 'dingtalk_write_markdown',
        label: '写入Markdown',
        method: 'POST',
        path: '/dingtalk_api/write_markdown/',
        payloadTemplate: {
          workbook_id: '',
          sheet_name: 'Sheet1',
          markdown_content: '### ARL 通知测试',
          operator_id: '',
        },
      },
    ],
  },
  {
    id: 'api_console',
    label: 'API管理',
    description: '管理 FOFA / Hunter / Quake / Zoomeye 等三方 API 凭据',
    group: '系统集成',
    icon: Key,
  },
  {
    id: 'config_console',
    label: '配置管理',
    description: '管理扫描字典、并发参数、黑名单IP与域名解析器配置',
    group: '系统集成',
    icon: Settings,
  },
];

const TASK_DETAIL_TABS: Array<{ id: string; label: string }> = [
  { id: 'site', label: '站点' },
  { id: 'domain', label: '子域名' },
  { id: 'ip', label: 'IP' },
  { id: 'cert', label: 'SSL证书' },
  { id: 'service', label: '服务' },
  { id: 'fileleak', label: '文件泄露' },
  { id: 'url', label: 'URL信息' },
  { id: 'vuln', label: '风险' },
  { id: 'cip', label: 'C段' },
  { id: 'nuclei_result', label: 'nuclei' },
  { id: 'stat_finger', label: '指纹统计' },
  { id: 'wih', label: 'WIH' },
];

function buildUrl(path: string, query?: JsonValue): string {
  const p = path.startsWith('/') ? path : `/${path}`;
  const full = `${API_BASE}${p}`;
  if (!query || Object.keys(query).length === 0) return full;

  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    params.append(key, String(value));
  });

  const qs = params.toString();
  return qs ? `${full}?${qs}` : full;
}

function toggleTrailingSlash(path: string): string | null {
  if (!path || path === '/') return null;
  if (path.endsWith('/')) {
    return path.slice(0, -1);
  }
  return `${path}/`;
}

function sanitizeUiMessage(value: any, maxLength = 300): string {
  if (value === null || value === undefined) return '';
  let text = String(value);
  // 统一移除 script/html 标签，避免接口返回原样展示脚本片段。
  text = text.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, ' ');
  text = text.replace(/<\/?[^>]+>/g, ' ');
  text = text.replace(/[\u0000-\u001f\u007f]+/g, ' ');
  text = text.replace(/\s+/g, ' ').trim();
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

function extractErrorMessage(data: any): string {
  if (!data) return '请求失败';
  if (typeof data === 'string') return sanitizeUiMessage(data) || '请求失败';
  if (Number(data.code) === 401) return '认证失败，请检查用户名密码或重新登录';

  const pickNestedMessage = (obj: any): string => {
    if (!obj || typeof obj !== 'object') return '';
    const directKeys = ['error_message', 'error', 'message', 'msg', 'errmsg', 'errMsg', 'detail'];
    for (const key of directKeys) {
      const value = (obj as Record<string, any>)?.[key];
      if (typeof value === 'string' && value.trim()) {
        const text = sanitizeUiMessage(value);
        if (text) return text;
      }
    }
    if (Array.isArray((obj as Record<string, any>)?.missing_fields) && (obj as Record<string, any>).missing_fields.length > 0) {
      return `缺少配置: ${(obj as Record<string, any>).missing_fields.join(', ')}`;
    }
    return '';
  };

  const nestedSources = [data?.data, data?.detail, data];
  for (const source of nestedSources) {
    const text = pickNestedMessage(source);
    if (text) return text;
  }

  return '请求失败';
}

function normalizeListData(data: any): {
  items: any[];
  total: number;
  page: number;
  size: number;
} {
  const source = data && data.data && Array.isArray(data.data.items) ? data.data : data;
  const items = Array.isArray(source?.items) ? source.items : [];
  const total = Number(source?.total ?? items.length);
  const page = Number(source?.page ?? 1);
  const size = Number((source?.size ?? items.length) || 20);
  return { items, total, page, size };
}

function sanitizeFilename(fileName: string): string {
  return fileName.replace(/[\\/:*?"<>|]/g, '_');
}

function normalizeRowIdValue(value: any): string {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (typeof value === 'object') {
    const candidates = ['$oid', '_id', 'id', 'task_id', 'job_id', 'oid'];
    for (const key of candidates) {
      const nested = (value as Record<string, any>)?.[key];
      if (typeof nested === 'string' || typeof nested === 'number') {
        const text = String(nested).trim();
        if (text) return text;
      }
    }
  }
  return '';
}

async function requestApi(token: string, path: string, options: ApiRequestOptions = {}) {
  const method = options.method ?? 'GET';
  const buildFetchOptions = (): RequestInit => {
    const headers: Record<string, string> = {};
    if (token) {
      headers.Token = token;
    }

    const fetchOptions: RequestInit = {
      method,
      headers,
      credentials: 'same-origin',
    };

    if (method !== 'GET' && options.body !== undefined) {
      if (options.body instanceof FormData) {
        fetchOptions.body = options.body;
      } else {
        headers['Content-Type'] = 'application/json';
        fetchOptions.body = JSON.stringify(options.body);
      }
    }
    return fetchOptions;
  };

  const primaryPath = path.startsWith('/') ? path : `/${path}`;
  const fallbackPath = toggleTrailingSlash(primaryPath);
  const primaryUrl = buildUrl(primaryPath, options.query);

  let response = await fetch(primaryUrl, buildFetchOptions());
  if ((response.status === 404 || response.status === 405) && fallbackPath && fallbackPath !== primaryPath) {
    const fallbackUrl = buildUrl(fallbackPath, options.query);
    response = await fetch(fallbackUrl, buildFetchOptions());
  }

  if (options.download) {
    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('application/json') || contentType.includes('text/json')) {
      let errJson: any = {};
      try {
        errJson = await response.json();
      } catch {
        errJson = {};
      }

      if (!response.ok || (errJson?.code && Number(errJson.code) !== 200)) {
        throw new Error(extractErrorMessage(errJson) || `下载失败: HTTP ${response.status}`);
      }

      throw new Error('下载失败，服务端未返回文件流');
    }

    if (!response.ok) {
      const fallbackText = await response.text();
      throw new Error(sanitizeUiMessage(fallbackText) || `下载失败: HTTP ${response.status}`);
    }

    const blob = await response.blob();
    const contentDisposition = response.headers.get('content-disposition') || '';
    const match = contentDisposition.match(/filename\*=UTF-8''([^;]+)|filename=([^;]+)/i);
    const rawName = decodeURIComponent((match?.[1] || match?.[2] || 'arl-export.bin').replace(/"/g, '').trim());
    const fileName = sanitizeFilename(rawName);

    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objectUrl);

    return { code: 200, message: 'downloaded', data: { fileName } };
  }

  const text = await response.text();
  let data: any = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }

  if (!response.ok) {
    if (typeof data?.raw === 'string' && data.raw) {
      throw new Error(`HTTP ${response.status}: ${sanitizeUiMessage(data.raw)}`);
    }
    throw new Error(`HTTP ${response.status}: ${extractErrorMessage(data)}`);
  }

  if (typeof data?.code === 'number' && data.code !== 200) {
    throw new Error(extractErrorMessage(data));
  }

  if (typeof data?.raw === 'string' && data.raw) {
    throw new Error(`接口返回非JSON: ${sanitizeUiMessage(data.raw)}`);
  }

  if (typeof data?.message === 'string') {
    data.message = sanitizeUiMessage(data.message);
  }
  if (typeof data?.error === 'string') {
    data.error = sanitizeUiMessage(data.error);
  }
  if (typeof data?.detail === 'string') {
    data.detail = sanitizeUiMessage(data.detail);
  }

  return data;
}

function truncateText(value: string, max = 120): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}...`;
}

function isDeleteAction(action: ModuleAction): boolean {
  const id = String(action?.id || '').toLowerCase();
  const label = String(action?.label || '').toLowerCase();
  const path = String(action?.path || '').toLowerCase();
  return id.includes('delete') || label.includes('删除') || path.includes('/delete/');
}

function truncateMiddleText(value: string, max = 48, head = 18, tail = 16): string {
  const text = String(value ?? '').trim();
  if (!text) return '-';
  if (text.length <= max) return text;
  const safeHead = Math.max(6, Math.min(head, Math.floor((max - 3) / 2)));
  const safeTail = Math.max(4, Math.min(tail, max - safeHead - 3));
  return `${text.slice(0, safeHead)}...${text.slice(-safeTail)}`;
}

function isLikelyIdColumn(column: string): boolean {
  const key = String(column || '').toLowerCase();
  if (!key) return false;
  return key === '_id' || key.endsWith('_id') || key === 'taskid' || key === 'job_id';
}

function formatExternalFilterChipText(key: string, value: any): string {
  const keyText = String(key || '').trim();
  const valueText = String(value ?? '').trim();
  if (!valueText) return `${keyText}=-`;

  if (isLikelyIdColumn(keyText)) {
    const parts = valueText.replace(/,/g, ' ').split(/\s+/).filter((item) => item);
    if (parts.length > 1) {
      return `${keyText}=${truncateMiddleText(parts[0], 32, 12, 10)} ... 共${parts.length}项`;
    }
    return `${keyText}=${truncateMiddleText(valueText, 44, 20, 18)}`;
  }

  return `${keyText}=${truncateMiddleText(valueText, 64, 28, 26)}`;
}

function normalizeValue(value: any): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'string') return truncateText(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '-';
    const normalized = value
      .map((item) => {
        if (item === null || item === undefined) return '';
        if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
          return String(item);
        }
        return JSON.stringify(item);
      })
      .filter((item) => item)
      .join(', ');
    return truncateText(normalized || '-');
  }
  if (typeof value === 'object') return truncateText(JSON.stringify(value));
  return truncateText(String(value));
}

const WIH_SENSITIVE_RECORD_TYPE_SET = new Set([
  'app_key',
  'api_key',
  'access_key',
  'secret_key',
  'client_secret',
  'private_key',
  'authorization',
  'token',
  'jwt',
  'password',
  'passwd',
  'credential',
]);

const WIH_SENSITIVE_CONTENT_KEYWORDS = [
  'app_key',
  'api_key',
  'access_key',
  'secret_key',
  'client_secret',
  'private_key',
  'authorization: bearer',
  'password',
  'passwd',
  'token',
  'jwt',
];

function isSensitiveWihRow(row: any): boolean {
  const recordType = String(row?.record_type || '').trim().toLowerCase();
  const content = String(row?.content || '').trim().toLowerCase();
  if (!recordType && !content) return false;
  if (recordType.startsWith('trufflehog_')) return true;
  if (WIH_SENSITIVE_RECORD_TYPE_SET.has(recordType)) return true;
  if (recordType.endsWith('_key') || recordType.endsWith('_token')) return true;
  return WIH_SENSITIVE_CONTENT_KEYWORDS.some((keyword) => content.includes(keyword));
}

function getWihRecordTypeTagClass(recordType: string, sensitive: boolean): string {
  const normalized = String(recordType || '').trim().toLowerCase();
  if (normalized.startsWith('trufflehog_')) {
    return 'inline-flex items-center rounded-full border border-brand-danger/45 bg-brand-danger/15 px-2.5 py-1 text-[11px] font-black text-brand-danger';
  }
  if (sensitive) {
    return 'inline-flex items-center rounded-full border border-brand-warning/45 bg-brand-warning/15 px-2.5 py-1 text-[11px] font-black text-brand-warning';
  }
  return 'inline-flex items-center rounded-full border border-brand-border bg-brand-bg/70 px-2.5 py-1 text-[11px] font-semibold text-brand-text-muted';
}

function buildCidrPrefix(value: any): string {
  const text = String(value ?? '').trim();
  if (!text || text === '-') return '';
  const cidrMatch = text.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?:\/\d{1,2})?$/);
  if (cidrMatch?.[1]) return `${cidrMatch[1]}.`;
  const prefixMatch = text.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.?$/);
  if (prefixMatch?.[1]) return `${prefixMatch[1]}.`;
  return '';
}

function getValueByPath(source: any, path: string): any {
  if (!path || source === null || source === undefined) return undefined;
  if (!path.includes('.')) return source?.[path];
  const segments = path.split('.');
  let cursor: any = source;
  for (const segment of segments) {
    if (cursor === null || cursor === undefined) return undefined;
    if (Array.isArray(cursor)) {
      cursor = cursor
        .map((item) => {
          if (item && typeof item === 'object') return item[segment];
          return undefined;
        })
        .flatMap((item) => (Array.isArray(item) ? item : [item]))
        .filter((item) => item !== undefined && item !== null);
      continue;
    }
    if (typeof cursor !== 'object') return undefined;
    cursor = cursor[segment];
  }
  return cursor;
}

function getTaskStatusLabel(rawStatus: any): string {
  const normalized = String(rawStatus ?? '').toLowerCase();
  if (!normalized) return '未知';
  if (normalized === 'waiting') return '等待中';
  if (normalized === 'running') return '运行中';
  if (normalized === 'done') return '已完成';
  if (normalized === 'stop') return '已停止';
  if (normalized === 'error') return '异常';
  if (/^\w+\s+\d+\/\d+$/i.test(normalized)) return normalized;
  if (normalized.includes('run') || normalized.includes('wait') || normalized.includes('queue') || normalized.includes('start')) return '运行中';
  if (normalized.includes('done') || normalized.includes('finish') || normalized.includes('success')) return '已完成';
  if (normalized.includes('stop') || normalized.includes('cancel')) return '已停止';
  if (normalized.includes('error') || normalized.includes('fail')) return '异常';
  return normalized;
}

function getTaskTypeLabel(rawType: any): string {
  const mapping: Record<string, string> = {
    domain: '域名任务',
    ip: 'IP任务',
    risk_cruising: '风险巡航任务',
    fofa: 'FOFA任务',
    asset_site_add: '添加站点任务',
    asset_site_update: '站点更新任务',
    asset_wih_update: 'WIH更新任务',
  };
  const normalized = String(rawType ?? '').toLowerCase();
  return mapping[normalized] || normalizeValue(rawType);
}

function buildTaskStatisticSummary(row: any): string {
  const stat = row?.statistic;
  if (!stat || typeof stat !== 'object' || Array.isArray(stat)) return '-';
  const siteCnt = Number(stat.site_cnt || 0);
  const domainCnt = Number(stat.domain_cnt || 0);
  const ipCnt = Number(stat.ip_cnt || 0);
  const vulnCnt = Number(stat.vuln_cnt || 0);
  return `站点:${siteCnt} 域名:${domainCnt} IP:${ipCnt} 风险:${vulnCnt}`;
}

function buildTaskOptionsSummary(row: any): string {
  const options = row?.options;
  if (!options || typeof options !== 'object' || Array.isArray(options)) return '-';
  const enabled = Object.entries(options)
    .filter(([, value]) => value === true)
    .map(([key]) => fieldLabelMap[key] || humanizeField(key));
  if (enabled.length === 0) return '未开启可选项';
  return enabled.map((label, index) => `${index + 1}. ${label}`).join('\n');
}

function parseListFromString(text: string): string[] {
  const normalized = text.trim();
  if (!normalized) return [];

  const tryParseJson = (): string[] => {
    if (!(normalized.startsWith('[') && normalized.endsWith(']'))) return [];
    try {
      const parsed = JSON.parse(normalized);
      if (!Array.isArray(parsed)) return [];
      return parsed
        .map((item) => String(item ?? '').trim())
        .filter((item) => item);
    } catch {
      return [];
    }
  };

  const jsonTokens = tryParseJson();
  if (jsonTokens.length > 0) return jsonTokens;

  const pyListMatch = normalized.match(/^\[(.*)\]$/);
  if (pyListMatch) {
    const body = pyListMatch[1].trim();
    if (!body) return [];
    return body
      .split(/\s*,\s*/)
      .map((item) => item.trim().replace(/^['"]|['"]$/g, ''))
      .filter((item) => item);
  }

  return normalized
    .split(/[,\uFF0C;\uFF1B\r\n\t\s]+/)
    .map((item) => item.trim())
    .filter((item) => item);
}

function formatTokenListText(value: any): string {
  if (value === null || value === undefined) return '-';
  if (Array.isArray(value)) {
    const tokens = value
      .flatMap((item) => parseListFromString(String(item || '')))
      .filter((item) => item);
    return tokens.length > 0 ? tokens.join('\n') : '-';
  }
  const text = String(value).trim();
  if (!text) return '-';
  const tokens = parseListFromString(text);
  if (tokens.length > 1) return tokens.join('\n');
  return tokens[0] || text;
}

function formatHeaderLines(value: any): string {
  if (value === null || value === undefined) return '-';

  let source = value;
  if (typeof source === 'string') {
    const text = source.trim();
    if (!text) return '-';
    try {
      source = JSON.parse(text);
    } catch {
      if (text.includes('\n')) {
        return text
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line)
          .slice(0, 12)
          .join('\n');
      }
      return truncateText(text, 360);
    }
  }

  const lines: string[] = [];
  const appendLine = (key: string, item: any) => {
    let itemText = '';
    if (item === null || item === undefined) {
      itemText = '';
    } else if (Array.isArray(item)) {
      itemText = item.map((part) => String(part ?? '')).filter((part) => part).join(', ');
    } else if (typeof item === 'object') {
      itemText = JSON.stringify(item);
    } else {
      itemText = String(item);
    }
    const normalizedValue = truncateText(itemText, 240);
    lines.push(key ? `${key}: ${normalizedValue}` : normalizedValue);
  };

  if (Array.isArray(source)) {
    source.forEach((item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        Object.entries(item).forEach(([key, subItem]) => appendLine(key, subItem));
      } else {
        appendLine('', item);
      }
    });
  } else if (source && typeof source === 'object') {
    Object.entries(source).forEach(([key, item]) => appendLine(key, item));
  } else {
    return truncateText(String(source), 360);
  }

  if (lines.length === 0) return '-';
  if (lines.length > 12) {
    return `${lines.slice(0, 12).join('\n')}\n...`;
  }
  return lines.join('\n');
}

function formatCertSummary(row: any): string {
  const cert = row?.cert && typeof row.cert === 'object' ? row.cert : {};
  const sslSecurity = cert?.ssl_security && typeof cert.ssl_security === 'object' ? cert.ssl_security : {};
  const toText = (value: any, max = 420): string => {
    if (value === null || value === undefined) return '-';
    if (Array.isArray(value)) {
      const text = value.map((item) => String(item ?? '')).filter((item) => item).join(', ');
      return truncateText(text || '-', max);
    }
    if (typeof value === 'object') {
      return truncateText(JSON.stringify(value), max);
    }
    return truncateText(String(value), max);
  };
  const subjectDn = toText(cert?.subject_dn);
  const issuerDn = toText(cert?.issuer_dn);
  const san = toText(cert?.extensions?.subjectAltName, 720);
  const serialNumber = toText(cert?.serial_number);
  const validityStart = toText(cert?.validity?.start);
  const validityEnd = toText(cert?.validity?.end);
  const sha256 = toText(cert?.fingerprint?.sha256);
  const sha1 = toText(cert?.fingerprint?.sha1);
  const md5 = toText(cert?.fingerprint?.md5);
  const protocolNamesFromItems = Array.isArray(sslSecurity?.protocols)
    ? sslSecurity.protocols
      .map((item: any) => (item && typeof item === 'object' ? String(item.name || '').trim() : String(item || '').trim()))
      .filter((item: string) => item)
    : [];
  const protocolNamesFromList = Array.isArray(sslSecurity?.protocol_names)
    ? sslSecurity.protocol_names.map((item: any) => String(item || '').trim()).filter((item: string) => item)
    : [];
  const protocolNames = Array.from(new Set([...protocolNamesFromItems, ...protocolNamesFromList]));
  const protocolText = protocolNames.length > 0 ? protocolNames.join(', ') : '-';

  const leastStrength = toText(sslSecurity?.least_strength);
  const ecdheCountRaw = Number(sslSecurity?.ecdhe_count);
  const ecdheCount = Number.isFinite(ecdheCountRaw) ? String(ecdheCountRaw) : '-';

  const cipherItems = Array.isArray(sslSecurity?.cipher_suites)
    ? sslSecurity.cipher_suites.filter((item: any) => item && typeof item === 'object')
    : [];
  const cipherPreviewLines = cipherItems.slice(0, 16).map((item: any) => {
    const protocol = String(item.protocol || '').trim();
    const name = String(item.name || '').trim();
    const strength = String(item.strength || '').trim().toUpperCase();
    if (!name) return '';
    let line = name;
    if (protocol) line = `[${protocol}] ${line}`;
    if (strength) line = `${line} (${strength})`;
    return line;
  }).filter((item: string) => item);
  if (cipherItems.length > 16) {
    cipherPreviewLines.push(`... 共 ${cipherItems.length} 条`);
  }

  const summaryLines = [
    '基本信息',
    `主题名称: ${subjectDn}`,
    `签发者名称: ${issuerDn}`,
    `使用者备用名称: ${san}`,
    `序列号: ${serialNumber}`,
    `时间: ${validityStart} 至 ${validityEnd}`,
    '协议支持',
    `支持协议: ${protocolText}`,
    `最弱加密强度: ${leastStrength}`,
    `ECDHE套件数: ${ecdheCount}`,
    '加密套件',
    `已启用套件: ${cipherPreviewLines.length > 0 ? '' : '-'}`,
    '指纹',
    `SHA-256: ${sha256}`,
    `SHA-1: ${sha1}`,
    `MD5: ${md5}`,
  ];

  if (cipherPreviewLines.length > 0) {
    cipherPreviewLines.forEach((line, index) => {
      summaryLines.push(`  ${index + 1}. ${line}`);
    });
  }

  return summaryLines.join('\n');
}

function formatCertHostCell(row: any): string {
  const ip = normalizeValue(row?.ip);
  const port = normalizeValue(row?.port);
  const endpoint = ip === '-' && port === '-' ? '-' : (port === '-' ? ip : `${ip}:${port}`);

  const domainCandidates: string[] = [];
  const sniDomain = String(row?.sni_domain || '').trim();
  if (sniDomain) {
    domainCandidates.push(sniDomain);
  }
  const primaryDomain = String(row?.domain || '').trim();
  if (primaryDomain) {
    domainCandidates.push(primaryDomain);
  }
  const domainList = Array.isArray(row?.domains) ? row.domains : [];
  domainList.forEach((item: any) => {
    const text = String(item || '').trim();
    if (text) domainCandidates.push(text);
  });
  const uniqueDomains = Array.from(new Set(domainCandidates));
  const domain = uniqueDomains.length > 0 ? uniqueDomains[0] : '-';

  // 证书列表优先展示域名身份，再附带IP端点，避免“看起来只按IP查证书”的误解。
  if (domain !== '-' && endpoint !== '-') return `${domain} -> ${endpoint}`;
  if (domain !== '-') return domain;
  return endpoint;
}

function formatDateTimeCell(value: any): string {
  if (value === null || value === undefined) return '-';
  const text = String(value).trim();
  if (!text || text === '-') return '-';

  // 统一展示为 YYYY-MM-DD HH:mm:ss，避免不同来源时间字符串长度不一致。
  const directMatch = text.match(/^(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2}:\d{2})/);
  if (directMatch) {
    return `${directMatch[1]} ${directMatch[2]}`;
  }

  const parsed = new Date(text);
  if (!Number.isNaN(parsed.getTime())) {
    const year = parsed.getFullYear();
    const month = String(parsed.getMonth() + 1).padStart(2, '0');
    const day = String(parsed.getDate()).padStart(2, '0');
    const hour = String(parsed.getHours()).padStart(2, '0');
    const minute = String(parsed.getMinutes()).padStart(2, '0');
    const second = String(parsed.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
  }

  return truncateText(text, 32);
}

function getTaskProgressPercent(row: any): number {
  const status = String(row?.status || '').toLowerCase();
  if (status === 'done') return 100;
  if (status === 'waiting') return 0;
  if (status === 'error' || status === 'stop') return 100;

  const ratioMatch = status.match(/(\d+)\s*\/\s*(\d+)/);
  if (ratioMatch) {
    const current = Number(ratioMatch[1]);
    const total = Number(ratioMatch[2]);
    if (Number.isFinite(current) && Number.isFinite(total) && total > 0) {
      const ratio = Math.round((current / total) * 100);
      return Math.min(99, Math.max(1, ratio));
    }
  }

  const options = row?.options && typeof row.options === 'object' ? row.options : {};
  const enabledOptionCount = Object.values(options).filter((value) => value === true).length;
  const serviceDoneCount = Array.isArray(row?.service) ? row.service.length : 0;
  const estimatedTotal = Math.max(enabledOptionCount + 2, 4);
  const estimated = Math.round((serviceDoneCount / estimatedTotal) * 100);
  if (status.includes('run') || status.includes('wait') || status.includes('queue') || status.includes('start')) {
    return Math.min(99, Math.max(5, estimated));
  }
  return Math.min(99, Math.max(0, estimated));
}

function formatModuleCellValue(moduleId: string, column: string, row: any): string {
  const value = getValueByPath(row, column);

  if (moduleId === 'task') {
    if (column === 'target') {
      return formatTokenListText(value);
    }
    if (column === 'status') {
      return getTaskStatusLabel(value);
    }
    if (column === 'type') {
      return getTaskTypeLabel(value);
    }
    if (column === 'statistic_summary') {
      return buildTaskStatisticSummary(row);
    }
    if (column === 'options_summary') {
      return buildTaskOptionsSummary(row);
    }
    if (column === 'progress') {
      return `${getTaskProgressPercent(row)}%`;
    }
    if (column === 'start_time' || column === 'end_time') {
      return formatDateTimeCell(value);
    }
  }

  if (moduleId === 'task_schedule') {
    if (column === 'target') {
      return formatTokenListText(value);
    }
    if (column === 'schedule_type') {
      const mapping: Record<string, string> = {
        future_scan: '定时下发',
        recurrent_scan: '周期下发',
      };
      return mapping[String(value || '').toLowerCase()] || normalizeValue(value);
    }
    if (column === 'status') {
      const mapping: Record<string, string> = {
        scheduled: '待调度',
        stop: '已停止',
        done: '已完成',
        error: '异常',
      };
      return mapping[String(value || '').toLowerCase()] || normalizeValue(value);
    }
    if (column === 'time_config') {
      const scheduleType = String(row?.schedule_type || '').toLowerCase();
      if (scheduleType === 'future_scan') {
        return normalizeValue(row?.start_date || '-');
      }
      if (scheduleType === 'recurrent_scan') {
        return normalizeValue(row?.cron || '-');
      }
      return normalizeValue(row?.cron || row?.start_date || '-');
    }
  }

  if (moduleId === 'scheduler') {
    if (column === 'last_run_date' || column === 'next_run_date') {
      return formatDateTimeCell(value);
    }
  }

  if (moduleId === 'asset_scope') {
    if (column === 'scope') {
      return formatTokenListText(value);
    }
  }

  if (moduleId === 'github_scheduler') {
    if (column === 'status') {
      const mapping: Record<string, string> = {
        running: '运行中',
        stop: '停止',
      };
      return mapping[String(value || '').toLowerCase()] || normalizeValue(value);
    }
  }

  if (moduleId === 'github_task') {
    if (column === 'status') {
      return getTaskStatusLabel(value);
    }
    if (column === 'result_count') {
      const count = Number(row?.statistic?.github_result_cnt || 0);
      return String(Number.isFinite(count) ? count : 0);
    }
  }

  if ((moduleId === 'github_result' || moduleId === 'github_monitor_result') && column === 'commit_date') {
    return normalizeValue(value ?? row?.commit_time ?? row?.found_time);
  }

  // 子域名关联IP较长时按行展示，提升可读性。
  if ((moduleId === 'domain' || moduleId === 'asset_domain') && column === 'ips') {
    return formatTokenListText(value);
  }

  // IP模块的多值端口/域名按行展示，避免单行过长。
  if ((moduleId === 'ip' || moduleId === 'asset_ip') && (column === 'port_info.port_id' || column === 'domain')) {
    return formatTokenListText(value);
  }

  if (moduleId === 'ip') {
    if (column === 'geo_summary') {
      const country = normalizeValue(row?.geo_city?.country_name);
      const region = normalizeValue(row?.geo_city?.region_name);
      const city = normalizeValue(row?.geo_city?.city_name);
      const composed = [country, region, city].filter((item) => item && item !== '-').join(' / ');
      return composed || '-';
    }
    if (column === 'asn_summary') {
      const asn = normalizeValue(row?.geo_asn?.number);
      const organization = normalizeValue(row?.geo_asn?.organization);
      if (asn !== '-' && organization !== '-') return `${asn} ${organization}`;
      if (asn !== '-') return asn;
      return organization;
    }
  }

  if (moduleId === 'cert') {
    if (column === 'host') {
      return formatCertHostCell(row);
    }
    if (column === 'cert_summary') {
      return formatCertSummary(row);
    }
  }

  if (moduleId === 'service' && column === 'ip_port') {
    const infoList = Array.isArray(row?.service_info)
      ? row.service_info
      : (row?.service_info && typeof row.service_info === 'object' ? [row.service_info] : []);

    const ipPortList = infoList
      .map((item: any) => {
        const rawIp = item?.ip;
        const rawPort = item?.port_id;
        const ip = rawIp === null || rawIp === undefined ? '' : String(rawIp).trim();
        const port = rawPort === null || rawPort === undefined ? '' : String(rawPort).trim();
        if (!ip && !port) return '';
        if (!port) return ip;
        if (!ip) return port;
        return `${ip}:${port}`;
      })
      .filter((item: string) => item && item !== '-');

    if (ipPortList.length === 0) return '-';
    return Array.from(new Set(ipPortList)).join('\n');
  }

  if (moduleId === 'service' && column === 'service_info.product') {
    const infoList = Array.isArray(row?.service_info)
      ? row.service_info
      : (row?.service_info && typeof row.service_info === 'object' ? [row.service_info] : []);

    const productList = infoList
      .flatMap((item: any) => {
        const productCandidates = [item?.product, item?.service_product, item?.serviceProduct];
        return productCandidates
          .filter((raw) => raw !== null && raw !== undefined)
          .flatMap((raw) =>
            String(raw)
              .split(/[\r\n,]+/)
              .map((part) => part.trim())
          );
      })
      .filter((item: string) => item && item !== '-');

    // 未开启服务识别(-sV)或服务指纹不足时，产品信息可能为空，这里给出明确提示。
    if (productList.length === 0) return '未识别';
    return Array.from(new Set(productList)).join(', ');
  }

  if (moduleId === 'vuln' && column === 'credential') {
    const verifyData = normalizeValue(row?.verify_data);
    if (verifyData !== '-') return verifyData;
    return normalizeValue(row?.verify_obj);
  }

  if (moduleId === 'asset_scope' && column === 'scope') {
    return formatTokenListText(value);
  }

  if ((moduleId === 'asset_site' || moduleId === 'site') && column === 'headers') {
    return formatHeaderLines(value);
  }

  if ((moduleId === 'asset_site' || moduleId === 'site') && column === 'finger' && Array.isArray(value)) {
    const fingerNames = value
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
          if (typeof item.name === 'string' && item.name.trim()) return item.name;
          if (typeof item.cms === 'string' && item.cms.trim()) return item.cms;
        }
        return '';
      })
      .filter((item) => item);
    if (fingerNames.length > 0) return truncateText(fingerNames.join(', '));
  }

  return normalizeValue(value);
}

function parseNumericValue(value: any): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const raw = value.trim().replace(/%$/, '');
    if (!raw) return null;
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function formatPercent(value: any): string {
  const numeric = parseNumericValue(value);
  if (numeric === null) return '-';
  return `${numeric.toFixed(1)}%`;
}

function formatCpuSummary(deviceInfo: any): string {
  const cpu = deviceInfo?.cpu;
  if (!cpu || typeof cpu !== 'object' || Array.isArray(cpu)) return normalizeValue(cpu);
  const count = parseNumericValue(cpu.count);
  const percent = formatPercent(cpu.percent);

  if (count !== null && percent !== '-') return `${Math.round(count)}核 / ${percent}`;
  if (count !== null) return `${Math.round(count)}核`;
  return percent;
}

function formatUsageSummary(value: any): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return normalizeValue(value);
  const used = normalizeValue(value.used);
  const total = normalizeValue(value.total);
  const percent = formatPercent(value.percent);
  const usedTotal = used !== '-' || total !== '-' ? `${used}/${total}` : '-';

  if (usedTotal !== '-' && percent !== '-') return `${usedTotal} (${percent})`;
  if (usedTotal !== '-') return usedTotal;
  return percent;
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

function toDatetimeLocalValue(value: any): string {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const directMatch = text.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(?::\d{2})?$/);
  if (directMatch) {
    return `${directMatch[1]}T${directMatch[2]}`;
  }
  return '';
}

function fromDatetimeLocalValue(value: string): string {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const localMatch = text.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2}))?$/);
  if (localMatch) {
    return `${localMatch[1]} ${localMatch[2]}:${localMatch[3] || '00'}`;
  }
  const spaceMatch = text.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})(?::(\d{2}))?$/);
  if (spaceMatch) {
    return `${spaceMatch[1]} ${spaceMatch[2]}:${spaceMatch[3] || '00'}`;
  }
  return text;
}

const fieldLabelMap: Record<string, string> = {
  name: '名称',
  target: '目标',
  policy_id: '策略ID',
  scope_id: '资产组ID',
  task_id: '任务ID',
  task_ids: '任务ID列表',
  job_id: '监控任务ID',
  keyword: '关键字',
  query: '查询语句',
  domain: '域名',
  site: '站点',
  interval: '间隔(秒)',
  cron: 'Cron表达式',
  start_date: '开始时间',
  schedule_type: '计划类型',
  task_tag: '任务标签',
  del_task_data: '删除关联数据',
  force_refresh_token: '强制刷新Token',
  workbook_id: '工作簿ID',
  sheet_name: '工作表',
  markdown_content: 'Markdown内容',
  operator_id: '操作人ID',
  parent_node_id: '父节点ID',
  workspace_id: '空间ID',
  notify_enable: '启用通知',
  notify_kb_enable: '推送知识库',
  dingding_notify: '钉钉通知',
  kb_notify_enable: '知识库通知',
  domain_brute: '域名爆破',
  domain_brute_type: '爆破字典类型',
  domain_dict: '域名爆破字典',
  file_leak_dict: '敏感文件泄漏字典',
  port_scan: '端口扫描',
  port_scan_type: '端口扫描类型',
  port_custom: '自定义端口',
  service_detection: '服务识别',
  service_brute: '弱口令爆破',
  os_detection: '操作系统识别',
  site_identify: '站点识别',
  site_capture: '站点截图',
  file_leak: '文件泄露',
  search_engines: '搜索引擎调用',
  site_spider: '站点爬虫',
  arl_search: 'ARL 历史查询',
  alt_dns: 'DNS字典智能生成',
  ssl_cert: 'SSL 证书获取',
  dns_query_plugin: '域名查询插件',
  skip_scan_cdn_ip: '跳过CDN',
  nuclei_scan: 'nuclei 调用',
  findvhost: 'Host 碰撞',
  web_info_hunter: 'WIH 调用',
};

type FlatPayloadField = {
  path: string;
  value: any;
  depth: number;
};

function flattenPayloadFields(payload: JsonValue, parent = ''): FlatPayloadField[] {
  const fields: FlatPayloadField[] = [];
  Object.entries(payload || {}).forEach(([key, value]) => {
    const path = parent ? `${parent}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      fields.push(...flattenPayloadFields(value, path));
    } else {
      fields.push({
        path,
        value,
        depth: path.split('.').length - 1,
      });
    }
  });
  return fields;
}

function updatePayloadValue(payload: JsonValue, path: string, value: any): JsonValue {
  const next = deepClone(payload || {});
  const parts = path.split('.');
  let cursor: any = next;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    if (!cursor[key] || typeof cursor[key] !== 'object' || Array.isArray(cursor[key])) {
      cursor[key] = {};
    }
    cursor = cursor[key];
  }
  cursor[parts[parts.length - 1]] = value;
  return next;
}

function getPayloadValue(payload: JsonValue, path: string): any {
  if (!payload || !path) return undefined;
  const parts = path.split('.');
  let cursor: any = payload;
  for (const key of parts) {
    if (cursor === null || cursor === undefined || typeof cursor !== 'object') {
      return undefined;
    }
    cursor = cursor[key];
  }
  return cursor;
}

function humanizeField(path: string): string {
  const direct = fieldLabelMap[path];
  if (direct) return direct;
  const key = path.split('.').pop() || path;
  if (fieldLabelMap[key]) return fieldLabelMap[key];
  return key
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^./, (s) => s.toUpperCase());
}

function applyPathTemplate(path: string, payload: JsonValue): string {
  return path.replace(/\{(\w+)\}/g, (_, key) => encodeURIComponent(String(payload[key] ?? '')));
}

function getModuleById(id: string): ModuleConfig {
  return modules.find((module) => module.id === id) || modules[0];
}

function resolveStoredModuleId(moduleId: string | null | undefined): string {
  const normalized = String(moduleId || '').trim();
  if (!normalized) return 'dashboard';
  return modules.some((module) => module.id === normalized) ? normalized : 'dashboard';
}

function LoginView({
  onLogin,
  loading,
  error,
}: {
  onLogin: (username: string, password: string) => Promise<void>;
  loading: boolean;
  error: string;
}) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('arlpass');

  return (
    <div className="min-h-screen bg-brand-bg text-white flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute -top-16 -left-16 w-72 h-72 rounded-full bg-brand-accent/20 blur-[120px] pointer-events-none" />
      <div className="absolute -bottom-20 -right-20 w-72 h-72 rounded-full bg-brand-secondary/20 blur-[120px] pointer-events-none" />

      <div className="relative z-10 w-full max-w-lg bg-brand-card/50 border border-brand-border backdrop-blur-xl rounded-[2rem] p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-12 h-12 rounded-2xl bg-brand-accent flex items-center justify-center shadow-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl md:text-2xl font-black tracking-tight leading-tight whitespace-nowrap overflow-hidden text-ellipsis">ARL互联网资产自动化收集系统</h1>
            <p className="text-sm text-brand-text-muted font-semibold mt-1">
              版本：{__ARL_VERSION__}
            </p>
          </div>
        </div>

        <form
          className="space-y-5"
          onSubmit={async (event) => {
            event.preventDefault();
            await onLogin(username, password);
          }}
        >
          <div className="space-y-2">
            <label className="text-xs font-black text-brand-text-muted uppercase tracking-wider">用户名</label>
            <div className="relative">
              <User className="w-4 h-4 text-brand-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="w-full bg-brand-bg border border-brand-border rounded-xl py-3 pl-10 pr-3 text-sm focus:outline-none focus:border-brand-accent"
                placeholder="admin"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-black text-brand-text-muted uppercase tracking-wider">密码</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-brand-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full bg-brand-bg border border-brand-border rounded-xl py-3 pl-10 pr-3 text-sm focus:outline-none focus:border-brand-accent"
                placeholder="请输入密码"
              />
            </div>
          </div>

          {error ? (
            <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-xl px-3 py-2">
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-brand-accent hover:opacity-90 disabled:opacity-60 transition px-5 py-3 rounded-xl font-black text-sm tracking-widest uppercase"
          >
            {loading ? '登录中...' : '登录系统'}
          </button>
        </form>
      </div>
    </div>
  );
}

function StatusPill({ text, type }: { text: string; type: 'success' | 'error' | 'info' }) {
  const className =
    type === 'success'
      ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'
      : type === 'error'
        ? 'text-brand-danger bg-brand-danger/10 border-brand-danger/30'
        : 'text-brand-accent bg-brand-accent/10 border-brand-accent/30';

  return (
    <span
      title={text}
      className={`inline-flex items-center max-w-[72vw] md:max-w-[36rem] text-xs px-3 py-1 rounded-full border font-semibold ${className}`}
    >
      <span className="truncate">{text}</span>
    </span>
  );
}

function DashboardView({
  token,
  onOpenModule,
  onQuickCreateTask,
}: {
  token: string;
  onOpenModule: (moduleId: string, nextFilters?: JsonValue) => void;
  onQuickCreateTask: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [lastUpdatedAt, setLastUpdatedAt] = useState('');
  const [stats, setStats] = useState({
    task: 0,
    scheduler: 0,
    asset_scope: 0,
    asset_site: 0,
    domain_total: 0,
    ip_total: 0,
    service_total: 0,
    url_total: 0,
    vuln: 0,
    github_task: 0,
    running_task: 0,
    new_assets_today: 0,
  });
  const [deviceInfo, setDeviceInfo] = useState<any>({});
  const [recentTasks, setRecentTasks] = useState<any[]>([]);
  const [assetTrend, setAssetTrend] = useState<any[]>([]);
  const [riskDistribution, setRiskDistribution] = useState<any[]>([]);
  const [networkTrend, setNetworkTrend] = useState<any[]>([]);
  const [recentLogs, setRecentLogs] = useState<any[]>([]);
  const [isLogPaused, setIsLogPaused] = useState(false);
  const [engineInfo, setEngineInfo] = useState<any>({});

  const resolveTaskStatus = (rawStatus: any): { text: string; type: 'success' | 'error' | 'info' } => {
    const normalized = String(rawStatus ?? '').toLowerCase();
    if (normalized.includes('done') || normalized.includes('finish') || normalized.includes('success')) return { text: '已完成', type: 'success' };
    if (normalized.includes('fail') || normalized.includes('error') || normalized.includes('stop') || normalized.includes('cancel')) {
      return { text: '异常/停止', type: 'error' };
    }
    if (normalized.includes('run') || normalized.includes('start') || normalized.includes('queue') || normalized.includes('wait')) {
      return { text: '进行中', type: 'info' };
    }
    return { text: normalized || '未知', type: 'info' };
  };

  const loadAssetOverviewCounts = useCallback(async () => {
    const targets = [
      { key: 'domain_total', path: '/domain/' },
      { key: 'ip_total', path: '/ip/' },
      { key: 'service_total', path: '/service/' },
      { key: 'url_total', path: '/url/' },
    ] as const;

    const responses = await Promise.all(
      targets.map((target) => requestApi(token, target.path, { method: 'GET', query: { page: 1, size: 1 } }))
    );

    const counts: Record<string, number> = {};
    responses.forEach((response, index) => {
      counts[targets[index].key] = Number(normalizeListData(response).total || 0);
    });
    return counts as {
      domain_total: number;
      ip_total: number;
      service_total: number;
      url_total: number;
    };
  }, [token]);

  const loadFallback = useCallback(async () => {
    const targets = [
      { key: 'task', path: '/task/' },
      { key: 'scheduler', path: '/scheduler/' },
      { key: 'asset_scope', path: '/asset_scope/' },
      { key: 'asset_site', path: '/asset_site/' },
      { key: 'vuln', path: '/vuln/' },
      { key: 'github_task', path: '/github_task/' },
    ] as const;

    const [responses, consoleInfo, recentTaskResponse, assetOverview] = await Promise.all([
      Promise.all(targets.map((target) => requestApi(token, target.path, { method: 'GET', query: { page: 1, size: 1 } }))),
      requestApi(token, '/console/info', { method: 'GET' }),
      requestApi(token, '/task/', { method: 'GET', query: { page: 1, size: 6, order: '-_id' } }),
      loadAssetOverviewCounts(),
    ]);

    const nextStats: any = {};
    responses.forEach((response, index) => {
      const normalized = normalizeListData(response);
      nextStats[targets[index].key] = normalized.total;
    });
    const recentTaskItems = normalizeListData(recentTaskResponse).items.slice(0, 6);
    const activeRecentTaskCount = recentTaskItems.filter((task: any) => {
      const status = String(task?.status || '').trim().toLowerCase();
      return Boolean(status) && !['done', 'stop', 'error'].includes(status);
    }).length;

    setStats((prev) => ({
      ...prev,
      task: Number(nextStats.task || 0),
      scheduler: Number(nextStats.scheduler || 0),
      asset_scope: Number(nextStats.asset_scope || 0),
      asset_site: Number(nextStats.asset_site || 0),
      domain_total: Number(assetOverview.domain_total || 0),
      ip_total: Number(assetOverview.ip_total || 0),
      service_total: Number(assetOverview.service_total || 0),
      url_total: Number(assetOverview.url_total || 0),
      vuln: Number(nextStats.vuln || 0),
      github_task: Number(nextStats.github_task || 0),
      running_task: Number(prev.running_task || 0) > 0 ? Number(prev.running_task || 0) : activeRecentTaskCount,
    }));
    setDeviceInfo(consoleInfo?.data?.device_info || {});
    setRecentTasks(recentTaskItems);
    setRecentLogs((prev) => (prev.length > 0 ? prev : [{ level: 'INFO', source: 'SCAN', msg: '当前为兼容模式，扫描日志接口不可用', time: '' }]));
    setLastUpdatedAt(new Date().toLocaleString('zh-CN', { hour12: false }));
  }, [token, loadAssetOverviewCounts]);

  const loadRecentLogs = useCallback(async (force = false) => {
    if (isLogPaused && !force) {
      return;
    }
    try {
      const response = await requestApi(token, '/console/recent_logs', { method: 'GET', query: { limit: 24 } });
      const logs = Array.isArray(response?.data?.recent_logs) ? response.data.recent_logs : [];
      if (logs.length > 0) {
        setRecentLogs(logs);
      }
    } catch {
      // 日志轮询失败时不打断仪表盘其他内容
    }
  }, [token, isLogPaused]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const dashboardInfo = await requestApi(token, '/console/dashboard', { method: 'GET' });
      const dashboardData = dashboardInfo?.data || {};
      if (!dashboardData?.stats) {
        throw new Error('仪表盘聚合数据为空');
      }

      const nextStats = dashboardData.stats || {};
      const hasActiveTasksField = Object.prototype.hasOwnProperty.call(nextStats, 'active_tasks');
      const activeTaskCount = hasActiveTasksField
        ? Number(nextStats.active_tasks || 0)
        : Number(nextStats.running_tasks || 0) + Number(nextStats.waiting_tasks || 0);
      const hasAssetOverviewFields = ['domain_total', 'ip_total', 'service_total', 'url_total']
        .some((key) => Object.prototype.hasOwnProperty.call(nextStats, key));
      const assetOverview = hasAssetOverviewFields
        ? {
            domain_total: Number(nextStats.domain_total || 0),
            ip_total: Number(nextStats.ip_total || 0),
            service_total: Number(nextStats.service_total || 0),
            url_total: Number(nextStats.url_total || 0),
          }
        : await loadAssetOverviewCounts();
      setStats({
        task: Number(nextStats.task_total || 0),
        scheduler: Number(nextStats.scheduler_total || 0),
        asset_scope: Number(nextStats.asset_scope_total || 0),
        asset_site: Number(nextStats.asset_site_total || 0),
        domain_total: Number(assetOverview.domain_total || 0),
        ip_total: Number(assetOverview.ip_total || 0),
        service_total: Number(assetOverview.service_total || 0),
        url_total: Number(assetOverview.url_total || 0),
        vuln: Number(nextStats.vuln_total || 0),
        github_task: Number(nextStats.github_task_total || 0),
        running_task: Number(activeTaskCount || 0),
        new_assets_today: Number(nextStats.new_assets_today || 0),
      });
      setDeviceInfo(dashboardData.device_info || {});
      setAssetTrend(Array.isArray(dashboardData.asset_trend_7d) ? dashboardData.asset_trend_7d : []);
      setRiskDistribution(Array.isArray(dashboardData.risk_distribution) ? dashboardData.risk_distribution : []);
      setNetworkTrend(Array.isArray(dashboardData.network_trend) ? dashboardData.network_trend : []);
      const dashboardRecentLogs = Array.isArray(dashboardData.recent_logs) ? dashboardData.recent_logs : [];
      if (!isLogPaused) {
        setRecentLogs(dashboardRecentLogs);
      }
      setEngineInfo(dashboardData.engine || {});
      setLastUpdatedAt(dashboardData.last_updated ? normalizeValue(dashboardData.last_updated) : new Date().toLocaleString('zh-CN', { hour12: false }));

      const recentTaskResponse = await requestApi(token, '/task/', { method: 'GET', query: { page: 1, size: 6, order: '-_id' } });
      setRecentTasks(normalizeListData(recentTaskResponse).items.slice(0, 6));
    } catch (err: any) {
      try {
        await loadFallback();
      } catch (fallbackErr: any) {
        setError(fallbackErr?.message || err?.message || '加载仪表盘失败');
      }
    } finally {
      setLoading(false);
    }
  }, [token, loadFallback, isLogPaused, loadAssetOverviewCounts]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (isLogPaused) {
      return;
    }
    void loadRecentLogs();
    const timer = window.setInterval(() => {
      void loadRecentLogs();
    }, 10000);
    return () => window.clearInterval(timer);
  }, [loadRecentLogs, isLogPaused]);

  // 兼容后端不同版本的字段命名
  const memoryInfo = deviceInfo?.memory || deviceInfo?.virtual_memory;
  const diskInfo = deviceInfo?.disk || deviceInfo?.disk_usage;
  const cpuPercent = parseNumericValue(deviceInfo?.cpu?.percent) || 0;
  const memoryPercent = parseNumericValue(memoryInfo?.percent) || 0;
  const diskPercent = parseNumericValue(diskInfo?.percent) || 0;
  const highRisk = Number((riskDistribution.find((item) => item?.name === '高危') || {}).value || 0);
  const cards = [
    { title: '总资产数', value: stats.asset_site, change: `+${stats.new_assets_today}`, isUp: true, icon: Globe, color: 'text-brand-accent' },
    { title: '活跃任务', value: stats.running_task, change: `总计 ${stats.task}`, isUp: true, icon: Activity, color: 'text-brand-secondary' },
    { title: '高危风险', value: highRisk, change: `总计 ${stats.vuln}`, isUp: highRisk === 0, icon: AlertTriangle, color: 'text-brand-danger' },
    { title: '今日新增', value: stats.new_assets_today, change: `分组 ${stats.asset_scope}`, isUp: true, icon: Shield, color: 'text-brand-warning' },
  ];
  const trendData = assetTrend.length > 0 ? assetTrend : [{ name: '周一', assets: stats.asset_site, vulns: stats.vuln }];
  const assetOverviewData = [
    { name: '子域名', value: Number(stats.domain_total || 0), color: '#14b8a6' },
    { name: 'IP', value: Number(stats.ip_total || 0), color: '#3b82f6' },
    { name: '服务', value: Number(stats.service_total || 0), color: '#22c55e' },
    { name: 'URL', value: Number(stats.url_total || 0), color: '#f97316' },
  ];
  const netData = networkTrend.length > 0 ? networkTrend : [{ time: '13:40', in: 120, out: 80 }];
  const logsData = recentLogs.length > 0 ? recentLogs : [{ level: 'INFO', source: 'SCAN', msg: '暂无扫描日志数据', time: '' }];
  const quickModules = [
    { id: 'task', label: '任务管理', desc: '下发、停止、导出扫描任务', icon: Activity, color: 'text-brand-accent' },
    { id: 'policy', label: '策略配置', desc: '维护标准化扫描策略模板', icon: FileCode, color: 'text-brand-secondary' },
    { id: 'scheduler', label: '资产监控', desc: '周期监控资产组与站点变化', icon: Monitor, color: 'text-brand-warning' },
    { id: 'asset_scope', label: '资产分组', desc: '维护范围并执行批量导出', icon: Globe, color: 'text-brand-danger' },
  ];
  const levelClassMap: Record<string, string> = {
    INFO: 'text-emerald-400',
    WARN: 'text-brand-warning',
    WARNING: 'text-brand-warning',
    ERROR: 'text-brand-danger',
    CRIT: 'text-brand-danger',
    DEBUG: 'text-sky-400',
  };

  const formatLogTime = (value: any): string => {
    if (!value) return '-';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return normalizeValue(value);
    return parsed.toLocaleString('zh-CN', { hour12: false });
  };

  const formatTime = (value: any): string => {
    if (!value) return '-';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return normalizeValue(value);
    return parsed.toLocaleString('zh-CN', { hour12: false });
  };

  const renderUsageBar = (title: string, percent: number, detail: string) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-[10px] font-black text-brand-text-muted uppercase tracking-widest">
        <span>{title}</span>
        <span className="text-white">{formatPercent(percent)}</span>
      </div>
      <div className="h-1.5 bg-brand-bg rounded-full overflow-hidden border border-brand-border">
        <div className="h-full bg-brand-accent rounded-full transition-all duration-300" style={{ width: `${Math.min(100, Math.max(0, percent))}%` }} />
      </div>
      <p className="text-[10px] text-brand-text-muted">{detail}</p>
    </div>
  );

  return (
    <div className="p-8 space-y-10">
      <div className="flex justify-between items-end gap-4 flex-wrap">
        <div>
          <h2 className="text-6xl font-black tracking-tighter leading-none mb-2">我的仪表盘</h2>
          <p className="text-brand-text-muted font-medium">ARL 互联网资产自动化收集系统 · 实时监控中</p>
        </div>
        <div className="text-right space-y-2">
          <p className="text-xs font-black text-brand-accent uppercase tracking-widest">最后更新</p>
          <p className="text-sm font-mono">{lastUpdatedAt || '-'}</p>
          <div className="flex gap-2 justify-end">
            <button
              onClick={onQuickCreateTask}
              className="px-5 py-2.5 rounded-xl bg-brand-accent text-white text-sm font-black uppercase tracking-wider hover:opacity-90 transition flex items-center gap-2"
            >
              <Plus className="w-[18px] h-[18px]" />
              新建任务
            </button>
            <button
              onClick={() => void load()}
              className="px-5 py-2.5 border border-brand-border rounded-xl text-sm font-semibold hover:bg-brand-card/60 transition flex items-center gap-2"
            >
              <RefreshCw className={`w-[18px] h-[18px] ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>
          </div>
        </div>
      </div>

      {error ? <div className="text-sm text-brand-danger border border-brand-danger/30 bg-brand-danger/10 rounded-xl px-4 py-3">{error}</div> : null}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {cards.map((card) => (
          <div key={card.title} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl hover:border-brand-accent/50 transition-all group shadow-xl shadow-black/20">
            <div className="flex justify-between items-start mb-4">
              <div className={`p-3 rounded-2xl bg-brand-bg border border-brand-border group-hover:scale-110 transition-transform ${card.color}`}>
                <card.icon className="w-6 h-6" />
              </div>
              <div className={`flex items-center gap-1 text-xs font-bold px-2 py-1 rounded-full ${card.isUp ? 'text-emerald-400 bg-emerald-400/10' : 'text-brand-danger bg-brand-danger/10'}`}>
                {card.isUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                {card.change}
              </div>
            </div>
            <h3 className="text-brand-text-muted text-xs font-black uppercase tracking-widest mb-1">{card.title}</h3>
            <p className="text-3xl font-black tracking-tighter">{card.value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-8">资产增长趋势 (7日)</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorAssetsTrend" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-accent)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--brand-accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="name" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} dy={10} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Area type="monotone" dataKey="assets" stroke="var(--brand-accent)" strokeWidth={3} fillOpacity={1} fill="url(#colorAssetsTrend)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-8">资产分布概览</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={assetOverviewData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Bar
                  dataKey="value"
                  radius={[8, 8, 8, 8]}
                  barSize={30}
                  background={{ fill: 'rgba(148,163,184,0.12)', radius: 8 }}
                >
                  {assetOverviewData.map((entry, index) => (
                    <Cell key={`asset-overview-${index}`} fill={entry?.color || '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-brand-secondary/10 rounded-xl">
              <Activity className="w-5 h-5 text-brand-secondary" />
            </div>
            <h3 className="text-xl font-black tracking-tight">系统监控</h3>
          </div>
          <div className="space-y-6 flex-1">
            {renderUsageBar('CPU 负载', cpuPercent, formatCpuSummary(deviceInfo))}
            {renderUsageBar('内存占用', memoryPercent, formatUsageSummary(memoryInfo))}
            {renderUsageBar('磁盘占用', diskPercent, formatUsageSummary(diskInfo))}
            <div className="h-28 mt-4">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={netData}>
                  <Area type="monotone" dataKey="in" stroke="var(--brand-accent)" fill="var(--brand-accent)" fillOpacity={0.1} strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-brand-warning/10 rounded-xl">
              <Zap className="w-5 h-5 text-brand-warning" />
            </div>
            <h3 className="text-xl font-black tracking-tight">ARL 引擎</h3>
          </div>
          <div className="flex-1 flex flex-col justify-center items-center">
            <div className="relative mb-6">
              <div className="w-20 h-20 rounded-full border-4 border-brand-warning/20" />
              <div className="absolute inset-0 w-20 h-20 rounded-full border-4 border-brand-warning border-t-transparent animate-spin" />
              <div className="absolute inset-0 flex items-center justify-center">
                <Zap className="w-8 h-8 text-brand-warning fill-brand-warning/20" />
              </div>
            </div>
            <div className="text-center space-y-1 mb-6">
              <p className="text-sm font-black">{normalizeValue(engineInfo?.version || 'ARL Engine')}</p>
              <p className="text-[10px] text-brand-text-muted font-bold uppercase tracking-widest">
                部署模式: {normalizeValue(engineInfo?.deploy_mode_text || '单机部署')}
              </p>
            </div>
            <p className="text-[11px] text-brand-text-muted mb-3">运行中任务: {normalizeValue(engineInfo?.running_tasks ?? stats.running_task ?? 0)}</p>
            <div className="w-full grid grid-cols-2 gap-2">
              <div className="p-3 bg-brand-bg/50 rounded-2xl border border-brand-border text-center">
                <p className="text-[10px] font-black text-brand-text-muted uppercase mb-1">待执行任务</p>
                <p className="text-lg font-black">{normalizeValue(engineInfo?.pending_tasks ?? engineInfo?.queue_pending ?? 0)}</p>
              </div>
              <div className="p-3 bg-brand-bg/50 rounded-2xl border border-brand-border text-center">
                <p className="text-[10px] font-black text-brand-text-muted uppercase mb-1">资源评分(估算)</p>
                <p className="text-lg font-black text-emerald-400">{formatPercent(engineInfo?.resource_score ?? engineInfo?.health_score ?? 100)}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-brand-accent/10 rounded-xl">
                <Terminal className="w-5 h-5 text-brand-accent" />
              </div>
              <h3 className="text-xl font-black tracking-tight">实时扫描日志</h3>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setIsLogPaused((prev) => !prev)}
                className={`text-xs font-black uppercase tracking-wider px-2 hover:underline ${isLogPaused ? 'text-brand-warning' : 'text-brand-secondary'}`}
              >
                {isLogPaused ? '继续' : '暂停'}
              </button>
              <button
                onClick={() => void loadRecentLogs(true)}
                className="text-xs font-black text-brand-accent uppercase tracking-wider hover:underline px-2"
              >
                刷新日志
              </button>
            </div>
          </div>
          <div className="flex-1 bg-black/20 rounded-2xl p-4 font-mono text-[10px] overflow-y-auto max-h-[320px]">
            {isLogPaused ? (
              <div className="mb-2 text-brand-warning border border-brand-warning/30 bg-brand-warning/10 rounded-lg px-2 py-1">扫描日志已暂停自动刷新</div>
            ) : null}
            {logsData.map((log, index) => {
              const level = String(log?.level || 'INFO').toUpperCase();
              const source = String(log?.source || 'SYSTEM').toUpperCase();
              return (
                <div key={`${source}-${level}-${index}`} className="py-2 border-b border-white/5 last:border-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`font-black shrink-0 w-12 ${levelClassMap[level] || 'text-brand-text-muted'}`}>{level}</span>
                    <span className="text-brand-text-muted">{source}</span>
                    <span className="ml-auto text-brand-text-muted">{formatLogTime(log?.time)}</span>
                  </div>
                  <p className="text-white/80 break-all leading-relaxed">{normalizeValue(log?.msg)}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-2 bg-brand-card/35 border border-brand-border rounded-3xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-black tracking-tight">最近任务</h3>
            <button
              onClick={() => onOpenModule('task')}
              className="text-sm font-black text-brand-accent border border-brand-accent/30 px-4 py-2 rounded-xl hover:bg-brand-accent/10 transition"
            >
              查看全部
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-brand-border">
                  <th className="py-2 pr-4 uppercase tracking-widest text-brand-text-muted">名称</th>
                  <th className="py-2 pr-4 uppercase tracking-widest text-brand-text-muted">状态</th>
                  <th className="py-2 pr-4 uppercase tracking-widest text-brand-text-muted">目标</th>
                  <th className="py-2 uppercase tracking-widest text-brand-text-muted">时间</th>
                </tr>
              </thead>
              <tbody>
                {recentTasks.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-brand-text-muted">
                      暂无任务数据
                    </td>
                  </tr>
                ) : (
                  recentTasks.map((task) => {
                    const statusInfo = resolveTaskStatus(task?.status);
                    const taskId = String(task?._id || task?.task_id || task?.id || '').trim();
                    return (
                      <tr key={String(task?._id || task?.task_id || task?.id || Math.random())} className="border-b border-brand-border/60 last:border-b-0">
                        <td className="py-3 pr-4 font-semibold">
                          {taskId ? (
                            <button
                              onClick={() => onOpenModule('site', { task_id: taskId })}
                              className="text-brand-accent hover:underline text-left"
                              title="点击查看该任务详情"
                            >
                              {normalizeValue(task?.name)}
                            </button>
                          ) : (
                            normalizeValue(task?.name)
                          )}
                        </td>
                        <td className="py-3 pr-4">
                          <StatusPill text={statusInfo.text} type={statusInfo.type} />
                        </td>
                        <td className="py-3 pr-4 font-mono">{normalizeValue(task?.target)}</td>
                        <td className="py-3 text-brand-text-muted">{formatTime(task?.create_time || task?.update_time || task?.start_time)}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-brand-card/35 border border-brand-border rounded-3xl p-6">
          <h3 className="text-lg font-black mb-4">快捷入口</h3>
          <div className="grid grid-cols-1 gap-3">
            {quickModules.map((entry) => (
              <button
                key={entry.id}
                onClick={() => onOpenModule(entry.id)}
                className="text-left bg-brand-bg/40 border border-brand-border rounded-2xl p-4 hover:border-brand-accent/45 hover:bg-brand-card/55 transition"
              >
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg bg-brand-card/60 border border-brand-border ${entry.color}`}>
                    <entry.icon className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="font-black text-sm">{entry.label}</p>
                    <p className="text-xs text-brand-text-muted mt-1">{entry.desc}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function SystemMonitorView({ token }: { token: string }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [resource, setResource] = useState<any>({});
  const [history, setHistory] = useState<any[]>([]);
  const [updatedAt, setUpdatedAt] = useState('');

  const loadFallback = useCallback(async () => {
    const dashboardInfo = await requestApi(token, '/console/dashboard', { method: 'GET' });
    const data = dashboardInfo?.data || {};
    const deviceInfo = data?.device_info || {};
    const memory = deviceInfo?.memory || deviceInfo?.virtual_memory || {};
    const disk = deviceInfo?.disk || deviceInfo?.disk_usage || {};
    const cpuPercent = parseNumericValue(deviceInfo?.cpu?.percent) || 0;
    const memoryPercent = parseNumericValue(memory?.percent) || 0;
    const diskPercent = parseNumericValue(disk?.percent) || 0;

    const fallbackHistory = Array.isArray(data?.network_trend)
      ? data.network_trend.map((item: any) => {
          const netIn = Number(item?.in || 0);
          const netOut = Number(item?.out || 0);
          return {
            time: normalizeValue(item?.time),
            cpu: cpuPercent,
            ram: memoryPercent,
            disk: diskPercent,
            net_in: netIn,
            net_out: netOut,
            net: netIn + netOut,
          };
        })
      : [];

    setResource({
      cpu_percent: cpuPercent,
      cpu_count: Number(deviceInfo?.cpu?.count || 0),
      memory_percent: memoryPercent,
      memory_used: normalizeValue(memory?.used),
      memory_total: normalizeValue(memory?.total),
      disk_percent: diskPercent,
      disk_used: normalizeValue(disk?.used),
      disk_total: normalizeValue(disk?.total),
      network_total_sent: '-',
      network_total_recv: '-',
      network_rate_in_kbps: Number((fallbackHistory[fallbackHistory.length - 1] || {}).net_in || 0),
      network_rate_out_kbps: Number((fallbackHistory[fallbackHistory.length - 1] || {}).net_out || 0),
      network_rate_total_kbps: Number((fallbackHistory[fallbackHistory.length - 1] || {}).net || 0),
      process_count: '-',
      boot_time: '-',
    });
    setHistory(fallbackHistory);
    setUpdatedAt(data?.last_updated ? normalizeValue(data.last_updated) : new Date().toLocaleString('zh-CN', { hour12: false }));
  }, [token]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const monitorInfo = await requestApi(token, '/console/system_monitor/', { method: 'GET' });
      const data = monitorInfo?.data || {};
      if (!data?.resource || typeof data.resource !== 'object') {
        throw new Error('系统监控数据为空');
      }
      setResource(data.resource || {});
      setHistory(Array.isArray(data.history_24h) ? data.history_24h : []);
      setUpdatedAt(data?.updated_at ? normalizeValue(data.updated_at) : new Date().toLocaleString('zh-CN', { hour12: false }));
    } catch (err: any) {
      try {
        await loadFallback();
      } catch (fallbackErr: any) {
        setError(fallbackErr?.message || err?.message || '加载系统监控失败');
      }
    } finally {
      setLoading(false);
    }
  }, [token, loadFallback]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [load]);

  const cpuPercent = parseNumericValue(resource?.cpu_percent) || 0;
  const memoryPercent = parseNumericValue(resource?.memory_percent) || 0;
  const diskPercent = parseNumericValue(resource?.disk_percent) || 0;
  const netIn = parseNumericValue(resource?.network_rate_in_kbps) || 0;
  const netOut = parseNumericValue(resource?.network_rate_out_kbps) || 0;
  const netTotal = parseNumericValue(resource?.network_rate_total_kbps) || 0;
  const chartData =
    history.length > 0
      ? history
      : [
          {
            time: '当前',
            cpu: cpuPercent,
            ram: memoryPercent,
            disk: diskPercent,
            net_in: netIn,
            net_out: netOut,
            net: netTotal,
          },
        ];

  const resourceCards: Array<{
    title: string;
    value: string;
    detail: string;
    percent: number;
    icon: React.ComponentType<{ className?: string }>;
    color: string;
  }> = [
    {
      title: 'CPU 使用率',
      value: formatPercent(cpuPercent),
      detail: `${normalizeValue(resource?.cpu_count)} 核`,
      percent: cpuPercent,
      icon: Cpu,
      color: 'text-brand-accent',
    },
    {
      title: '内存占用',
      value: `${normalizeValue(resource?.memory_used)} / ${normalizeValue(resource?.memory_total)}`,
      detail: formatPercent(memoryPercent),
      percent: memoryPercent,
      icon: Database,
      color: 'text-brand-secondary',
    },
    {
      title: '磁盘占用',
      value: `${normalizeValue(resource?.disk_used)} / ${normalizeValue(resource?.disk_total)}`,
      detail: formatPercent(diskPercent),
      percent: diskPercent,
      icon: Server,
      color: 'text-brand-warning',
    },
    {
      title: '网络速率',
      value: `${netTotal.toFixed(1)} KB/s`,
      detail: `入 ${netIn.toFixed(1)} / 出 ${netOut.toFixed(1)} KB/s`,
      percent: Math.min(100, Math.max(0, netTotal > 1000 ? 100 : netTotal / 10)),
      icon: Network,
      color: 'text-emerald-400',
    },
  ];

  return (
    <div className="p-8 space-y-8">
      <div className="flex justify-between items-end gap-4 flex-wrap">
        <div>
          <h2 className="text-6xl font-black tracking-tighter leading-none mb-2">系统监控</h2>
          <p className="text-brand-text-muted font-medium">实时监控主机资源、CPU、内存、磁盘与网络流量趋势</p>
        </div>
        <div className="text-right space-y-2">
          <p className="text-xs font-black text-brand-accent uppercase tracking-widest">最后更新</p>
          <p className="text-sm font-mono">{updatedAt || '-'}</p>
          <button
            onClick={() => void load()}
            className="px-5 py-2.5 border border-brand-border rounded-xl text-sm font-semibold hover:bg-brand-card/60 transition flex items-center gap-2"
            disabled={loading}
          >
            <RefreshCw className={`w-[18px] h-[18px] ${loading ? 'animate-spin' : ''}`} />
            刷新
          </button>
        </div>
      </div>

      {error ? <div className="text-sm text-brand-danger border border-brand-danger/30 bg-brand-danger/10 rounded-xl px-4 py-3">{error}</div> : null}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {resourceCards.map((item) => (
          <div key={item.title} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl shadow-xl shadow-black/20">
            <div className="flex items-center justify-between mb-5">
              <div className={`p-2.5 rounded-xl bg-brand-bg border border-brand-border ${item.color}`}>
                <item.icon className="w-5 h-5" />
              </div>
              <span className="text-xs font-black text-brand-text-muted">{item.detail}</span>
            </div>
            <h3 className="text-xs font-black uppercase tracking-wider text-brand-text-muted mb-1">{item.title}</h3>
            <p className="text-2xl font-black tracking-tight">{item.value}</p>
            <div className="h-2 mt-4 rounded-full bg-brand-bg border border-brand-border overflow-hidden">
              <div className="h-full bg-brand-accent transition-all duration-300" style={{ width: `${Math.min(100, Math.max(0, item.percent))}%` }} />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-6">资源使用趋势</h3>
          <div className="h-[320px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Line type="monotone" dataKey="cpu" stroke="var(--brand-accent)" strokeWidth={2.5} dot={false} />
                <Line type="monotone" dataKey="ram" stroke="var(--brand-secondary)" strokeWidth={2.5} dot={false} />
                <Line type="monotone" dataKey="disk" stroke="var(--brand-warning)" strokeWidth={2.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black tracking-tight mb-6">网络流量趋势</h3>
          <div className="h-[320px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="systemMonitorNetIn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-secondary)" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="var(--brand-secondary)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="systemMonitorNetOut" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-accent)" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="var(--brand-accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Area type="monotone" dataKey="net_in" stroke="var(--brand-secondary)" fillOpacity={1} fill="url(#systemMonitorNetIn)" strokeWidth={2.5} />
                <Area type="monotone" dataKey="net_out" stroke="var(--brand-accent)" fillOpacity={1} fill="url(#systemMonitorNetOut)" strokeWidth={2.5} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4">
          <p className="text-xs text-brand-text-muted uppercase tracking-wider">累计发送流量</p>
          <p className="text-2xl font-black mt-1">{normalizeValue(resource?.network_total_sent)}</p>
        </div>
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4">
          <p className="text-xs text-brand-text-muted uppercase tracking-wider">累计接收流量</p>
          <p className="text-2xl font-black mt-1">{normalizeValue(resource?.network_total_recv)}</p>
        </div>
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4">
          <p className="text-xs text-brand-text-muted uppercase tracking-wider">进程数量 / 启动时间</p>
          <p className="text-lg font-black mt-1">{normalizeValue(resource?.process_count)} / {normalizeValue(resource?.boot_time)}</p>
        </div>
      </div>
    </div>
  );
}

function ActionDialog({
  token,
  action,
  initialPayload,
  onClose,
  onSubmit,
}: {
  token: string;
  action: ModuleAction;
  initialPayload: JsonValue;
  onClose: () => void;
  onSubmit: (payload: JsonValue, file?: File | null) => Promise<void>;
}) {
  type TaskDomainDictOption = {
    label: string;
    path: string;
    source: string;
    exists: boolean;
    size: number;
    selected?: boolean;
  };

  const [formPayload, setFormPayload] = useState<JsonValue>(deepClone(initialPayload));
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [file, setFile] = useState<File | null>(null);

  const editable = action.allowPayloadEdit !== false;
  const isTaskCreate = action.id === 'create_task';
  const isAssetScopeCreate = action.id === 'asset_scope_add';
  const isAssetScopeAddScope = action.id === 'asset_scope_add_scope';
  const isAssetScopeAddScheduler = action.id === 'asset_scope_add_scheduler';
  const isAssetScopeAddSiteMonitor = action.id === 'asset_scope_add_site_monitor';
  const isAssetScopeAddWihMonitor = action.id === 'asset_scope_add_wih_monitor';
  const isTaskScheduleCreate = action.id === 'task_schedule_add';
  const isFofaSubmitAction = action.id === 'fofa_submit' || action.id === 'fofa_submit_center';
  const isFofaTestAction = action.id === 'fofa_test';
  const isFofaAction = isFofaSubmitAction || isFofaTestAction;
  const shouldLoadPolicyOptions = isTaskScheduleCreate || isAssetScopeAddScheduler || isFofaSubmitAction;
  const isPolicySelectionRequired = isTaskScheduleCreate || isAssetScopeAddScheduler;
  const isGithubSchedulerAction = action.id === 'github_scheduler_add' || action.id === 'github_scheduler_update';
  const isPolicyAction = action.id === 'policy_add' || action.id === 'policy_edit';
  const shouldLoadDictOptions = isTaskCreate || isPolicyAction;
  const fields = useMemo(() => flattenPayloadFields(formPayload), [formPayload]);
  const displayFields = useMemo(() => fields, [fields]);
  const policyRootPath = action.id === 'policy_edit' ? 'policy_data.policy' : 'policy';
  const policyNamePath = action.id === 'policy_edit' ? 'policy_data.name' : 'name';
  const policyDescPath = action.id === 'policy_edit' ? 'policy_data.desc' : 'desc';
  const taskFeatureSections = useMemo(() => {
    if (!isTaskCreate) return [];
    const isBooleanField = (key: string) => typeof formPayload?.[key] === 'boolean';
    const sections = [
      {
        title: '域名探测',
        // “域名爆破”在任务级固定开启，这里隐藏开关，避免与字典配置形成重复认知。
        keys: ['alt_dns', 'dns_query_plugin', 'arl_search'],
      },
      {
        title: '网络探测',
        keys: ['port_scan', 'service_detection', 'os_detection', 'ssl_cert', 'skip_scan_cdn_ip'],
      },
      {
        title: 'Web与风险',
        keys: ['site_identify', 'search_engines', 'site_spider', 'site_capture', 'file_leak', 'nuclei_scan', 'findvhost', 'web_info_hunter', 'dingding_notify'],
      },
    ];
    return sections
      .map((section) => ({
        title: section.title,
        keys: section.keys.filter(isBooleanField),
      }))
      .filter((section) => section.keys.length > 0);
  }, [formPayload, isTaskCreate]);
  const taskFeatureKeys = useMemo(
    () => taskFeatureSections.flatMap((section) => section.keys),
    [taskFeatureSections]
  );
  const allTaskFeaturesEnabled =
    taskFeatureKeys.length > 0 && taskFeatureKeys.every((key) => Boolean(formPayload?.[key]));
  const setAllTaskFeatures = (enabled: boolean) => {
    setFormPayload((prev) => {
      const next = deepClone(prev || {});
      taskFeatureKeys.forEach((key) => {
        next[key] = enabled;
      });
      return next;
    });
  };
  const taskName = String(formPayload?.name ?? '');
  const taskTarget = String(formPayload?.target ?? '');
  const taskDomainDict = String(formPayload?.domain_dict ?? '');
  const taskFileLeakDict = String(formPayload?.file_leak_dict ?? '');
  const taskPortScanType = String(formPayload?.port_scan_type ?? 'test');
  const taskPortCustom = String(formPayload?.port_custom ?? '80,443');
  const taskScheduleName = String(formPayload?.name ?? '');
  const taskScheduleTarget = String(formPayload?.target ?? '');
  const taskScheduleType = String(formPayload?.schedule_type ?? 'future_scan') === 'recurrent_scan' ? 'recurrent_scan' : 'future_scan';
  const taskSchedulePolicyId = String(formPayload?.policy_id ?? '');
  const fofaTaskName = String(formPayload?.name ?? '');
  const fofaQueryText = String(formPayload?.query ?? '');
  const fofaPolicyId = String(formPayload?.policy_id ?? '');
  const taskScheduleCron = String(formPayload?.cron ?? '');
  const taskScheduleStartDate = toDatetimeLocalValue(formPayload?.start_date);
  const taskScheduleTag = String(formPayload?.task_tag ?? 'task') === 'risk_cruising' ? 'risk_cruising' : 'task';
  const taskScheduleNotifyEnable = Boolean(formPayload?.notify_enable);
  const taskScheduleNotifyKbEnable = Boolean(formPayload?.notify_kb_enable);
  const githubSchedulerName = String(formPayload?.name ?? '');
  const githubSchedulerKeyword = String(formPayload?.keyword ?? '');
  const githubSchedulerCron = String(formPayload?.cron ?? '');
  const githubSchedulerDingdingNotify = Boolean(formPayload?.dingding_notify);
  const githubSchedulerKbNotifyEnable = Boolean(formPayload?.kb_notify_enable);
  const scopeGroupName = String(formPayload?.name ?? '');
  const scopeType = String(formPayload?.scope_type ?? 'domain') === 'ip' ? 'ip' : 'domain';
  const scopeText = String(formPayload?.scope ?? '');
  const scopeAddTargetText = String(formPayload?.scope ?? '');
  const scopeMonitorRangeText = String(formPayload?.domain ?? '');
  const scopeMonitorIntervalHours = Math.max(1, Math.round((Number(formPayload?.interval || 86400) || 86400) / 3600));
  const policyName = String(getPayloadValue(formPayload, policyNamePath) ?? '');
  const policyDesc = String(getPayloadValue(formPayload, policyDescPath) ?? '');
  const policyDomainDict = String(getPayloadValue(formPayload, `${policyRootPath}.domain_dict`) ?? '');
  const policyFileLeakDict = String(getPayloadValue(formPayload, `${policyRootPath}.file_leak_dict`) ?? '');
  const policyPortScanType = String(getPayloadValue(formPayload, `${policyRootPath}.ip_config.port_scan_type`) ?? 'test');
  const policyPortCustom = String(getPayloadValue(formPayload, `${policyRootPath}.ip_config.port_custom`) ?? '80,443');
  const [policySearchKeyword, setPolicySearchKeyword] = useState('');
  const [policyPocKeyword, setPolicyPocKeyword] = useState('');
  const [policyBruteKeyword, setPolicyBruteKeyword] = useState('');
  const [policyPluginLoading, setPolicyPluginLoading] = useState(false);
  const [policyPluginError, setPolicyPluginError] = useState('');
  const [policyPocOptions, setPolicyPocOptions] = useState<Array<{ plugin_name: string; vul_name: string }>>([]);
  const [policyBruteOptions, setPolicyBruteOptions] = useState<Array<{ plugin_name: string; vul_name: string }>>([]);
  const [taskSchedulePolicyOptions, setTaskSchedulePolicyOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [taskSchedulePolicyLoading, setTaskSchedulePolicyLoading] = useState(false);
  const [taskSchedulePolicyError, setTaskSchedulePolicyError] = useState('');
  const [fofaTesting, setFofaTesting] = useState(false);
  const [fofaResultSize, setFofaResultSize] = useState<number | null>(null);
  const [taskDomainDictOptions, setTaskDomainDictOptions] = useState<TaskDomainDictOption[]>([]);
  const [taskDomainDictLoading, setTaskDomainDictLoading] = useState(false);
  const [taskDomainDictError, setTaskDomainDictError] = useState('');
  const [taskDefaultDomainDictPath, setTaskDefaultDomainDictPath] = useState('');
  const [taskFileLeakDictOptions, setTaskFileLeakDictOptions] = useState<TaskDomainDictOption[]>([]);
  const [taskFileLeakDictError, setTaskFileLeakDictError] = useState('');
  const [taskDefaultFileLeakDictPath, setTaskDefaultFileLeakDictPath] = useState('');

  const getPolicyPath = (suffix: string) => `${policyRootPath}.${suffix}`;
  const updatePolicyValue = (suffix: string, value: any) => {
    setFormPayload((prev) => updatePayloadValue(prev, getPolicyPath(suffix), value));
  };

  const extractPluginNames = (value: any): string[] => {
    if (!Array.isArray(value)) return [];
    return value
      .map((item) => String(item?.plugin_name || '').trim())
      .filter((item) => item);
  };

  const selectedPolicyPocNames = extractPluginNames(getPayloadValue(formPayload, getPolicyPath('poc_config')));
  const selectedPolicyBruteNames = extractPluginNames(getPayloadValue(formPayload, getPolicyPath('brute_config')));
  const policySiteOptionDefs = [
    { key: 'site_config.site_identify', label: '1. 站点识别' },
    { key: 'site_config.search_engines', label: '2. 搜索引擎调用' },
    { key: 'site_config.site_spider', label: '3. 站点爬虫' },
    { key: 'site_config.site_capture', label: '4. 站点截图' },
    { key: 'file_leak', label: '5. 文件泄露' },
    { key: 'site_config.nuclei_scan', label: '6. nuclei 调用' },
    { key: 'site_config.web_info_hunter', label: '7. WIH 调用' },
  ];
  const filteredPolicySiteOptions = policySiteOptionDefs.filter((item) => {
    const keyword = policySearchKeyword.trim().toLowerCase();
    if (!keyword) return true;
    return item.label.toLowerCase().includes(keyword);
  });
  const policySiteOptionAllEnabled =
    policySiteOptionDefs.length > 0 &&
    policySiteOptionDefs.every((item) => Boolean(getPayloadValue(formPayload, getPolicyPath(item.key))));
  const setPolicySiteOptionAll = (enabled: boolean) => {
    setFormPayload((prev) => {
      let next = deepClone(prev || {});
      policySiteOptionDefs.forEach((item) => {
        next = updatePayloadValue(next, getPolicyPath(item.key), enabled);
      });
      return next;
    });
  };
  const filteredPolicyPocOptions = policyPocOptions.filter((item) => {
    const keyword = policyPocKeyword.trim().toLowerCase();
    if (!keyword) return true;
    return item.plugin_name.toLowerCase().includes(keyword) || item.vul_name.toLowerCase().includes(keyword);
  });
  const filteredPolicyBruteOptions = policyBruteOptions.filter((item) => {
    const keyword = policyBruteKeyword.trim().toLowerCase();
    if (!keyword) return true;
    return item.plugin_name.toLowerCase().includes(keyword) || item.vul_name.toLowerCase().includes(keyword);
  });
  const policyPocAllSelected =
    policyPocOptions.length > 0 && policyPocOptions.every((item) => selectedPolicyPocNames.includes(item.plugin_name));
  const policyBruteAllSelected =
    policyBruteOptions.length > 0 && policyBruteOptions.every((item) => selectedPolicyBruteNames.includes(item.plugin_name));
  const taskDomainDictSelectOptions = useMemo(() => {
    const next = [...taskDomainDictOptions];
    const exists = next.some((item) => item.path === taskDomainDict);
    if (taskDomainDict && !exists) {
      next.push({
        label: taskDomainDict,
        path: taskDomainDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskDomainDictOptions, taskDomainDict]);
  const taskFileLeakDictSelectOptions = useMemo(() => {
    const next = [...taskFileLeakDictOptions];
    const exists = next.some((item) => item.path === taskFileLeakDict);
    if (taskFileLeakDict && !exists) {
      next.push({
        label: taskFileLeakDict,
        path: taskFileLeakDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskFileLeakDictOptions, taskFileLeakDict]);
  const policyDomainDictSelectOptions = useMemo(() => {
    const next = [...taskDomainDictOptions];
    const exists = next.some((item) => item.path === policyDomainDict);
    if (policyDomainDict && !exists) {
      next.push({
        label: policyDomainDict,
        path: policyDomainDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskDomainDictOptions, policyDomainDict]);
  const policyFileLeakDictSelectOptions = useMemo(() => {
    const next = [...taskFileLeakDictOptions];
    const exists = next.some((item) => item.path === policyFileLeakDict);
    if (policyFileLeakDict && !exists) {
      next.push({
        label: policyFileLeakDict,
        path: policyFileLeakDict,
        source: 'custom',
        exists: true,
        size: 0,
      });
    }
    return next;
  }, [taskFileLeakDictOptions, policyFileLeakDict]);

  const setPolicyPluginConfig = (field: 'poc_config' | 'brute_config', pluginNames: string[]) => {
    const payloadList = pluginNames.map((pluginName) => ({
      plugin_name: pluginName,
      enable: true,
    }));
    updatePolicyValue(field, payloadList);
  };

  const togglePolicyPluginSelection = (field: 'poc_config' | 'brute_config', pluginName: string, enabled: boolean) => {
    const currentList = field === 'poc_config' ? selectedPolicyPocNames : selectedPolicyBruteNames;
    const nextSet = new Set(currentList);
    if (enabled) {
      nextSet.add(pluginName);
    } else {
      nextSet.delete(pluginName);
    }
    setPolicyPluginConfig(field, Array.from(nextSet));
  };

  useEffect(() => {
    const nextPayload = deepClone(initialPayload);
    setFormPayload(nextPayload);
    setError('');
    setPolicySearchKeyword('');
    setPolicyPocKeyword('');
    setPolicyBruteKeyword('');
    setFofaTesting(false);
    setFofaResultSize(null);
  }, [initialPayload]);

  const normalizeFofaQueries = (rawQuery: string): string[] => {
    const lines = String(rawQuery || '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line);
    const seen = new Set<string>();
    const normalized: string[] = [];
    lines.forEach((line) => {
      if (seen.has(line)) return;
      seen.add(line);
      normalized.push(line);
    });
    return normalized;
  };

  const runFofaQueryTest = async () => {
    try {
      setError('');
      setFofaTesting(true);
      const queryItems = normalizeFofaQueries(fofaQueryText);
      if (queryItems.length === 0) {
        throw new Error('请填写查询语句（支持多行输入）');
      }

      const normalizedQuery = queryItems.join('\n');
      setFormPayload((prev) => updatePayloadValue(prev, 'query', normalizedQuery));

      const result = await requestApi(token, '/task_fofa/test', {
        method: 'POST',
        body: { query: normalizedQuery },
      });
      const totalSize = Number(result?.data?.size ?? 0);
      setFofaResultSize(Number.isFinite(totalSize) ? totalSize : 0);
    } catch (err: any) {
      setFofaResultSize(null);
      setError(err?.message || 'FOFA 语法测试失败');
    } finally {
      setFofaTesting(false);
    }
  };

  useEffect(() => {
    if (!shouldLoadDictOptions) {
      setTaskDomainDictOptions([]);
      setTaskDomainDictLoading(false);
      setTaskDomainDictError('');
      setTaskDefaultDomainDictPath('');
      setTaskFileLeakDictOptions([]);
      setTaskFileLeakDictError('');
      setTaskDefaultFileLeakDictPath('');
      return;
    }

    let cancelled = false;
    const loadTaskDomainDictOptions = async () => {
      setTaskDomainDictLoading(true);
      setTaskDomainDictError('');
      setTaskFileLeakDictError('');
      try {
        const response = await requestApi(token, '/api_console/scan_config/', { method: 'GET' });
        const data = response?.data || {};
        const options = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
        const fileLeakOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];
        const defaultPath = String(data?.scan_config?.domain_dict || '').trim();
        const defaultFileLeakPath = String(data?.scan_config?.file_leak_dict || '').trim();
        if (cancelled) return;

        const normalizedOptions = options
          .map((item: any) => ({
            label: String(item?.label || item?.path || '').trim(),
            path: String(item?.path || '').trim(),
            source: String(item?.source || 'custom').trim() || 'custom',
            exists: Boolean(item?.exists),
            size: Number(item?.size || 0),
            selected: Boolean(item?.selected),
          }))
          .filter((item: TaskDomainDictOption) => item.path);
        const normalizedFileLeakOptions = fileLeakOptions
          .map((item: any) => ({
            label: String(item?.label || item?.path || '').trim(),
            path: String(item?.path || '').trim(),
            source: String(item?.source || 'custom').trim() || 'custom',
            exists: Boolean(item?.exists),
            size: Number(item?.size || 0),
            selected: Boolean(item?.selected),
          }))
          .filter((item: TaskDomainDictOption) => item.path);

        // 新建任务默认优先选择 domain_2w.txt，找不到时回退到扫描配置默认字典。
        const preferredBigDictPath =
          normalizedOptions.find((item) => /domain_2w\.txt$/i.test(item.path) || /domain_2w\.txt/i.test(item.label))?.path || '';
        const effectiveDefaultPath = preferredBigDictPath || defaultPath;

        setTaskDomainDictOptions(normalizedOptions);
        setTaskFileLeakDictOptions(normalizedFileLeakOptions);
        setTaskDefaultDomainDictPath(effectiveDefaultPath);
        setTaskDefaultFileLeakDictPath(defaultFileLeakPath);

        setFormPayload((prev) => {
          let next = prev;
          if (isTaskCreate) {
            const currentDict = String(prev?.domain_dict || '').trim();
            const currentFileLeakDict = String(prev?.file_leak_dict || '').trim();
            if (!currentDict && effectiveDefaultPath) {
              next = updatePayloadValue(next, 'domain_dict', effectiveDefaultPath);
            }
            if (!currentFileLeakDict && defaultFileLeakPath) {
              next = updatePayloadValue(next, 'file_leak_dict', defaultFileLeakPath);
            }
            return next;
          }

          if (isPolicyAction) {
            const domainDictPath = `${policyRootPath}.domain_dict`;
            const fileLeakDictPath = `${policyRootPath}.file_leak_dict`;
            const currentDict = getPayloadValue(prev, domainDictPath);
            const currentFileLeakDict = getPayloadValue(prev, fileLeakDictPath);
            // 策略字典支持“跟随配置管理默认值”，因此只补齐空串字段，不强制写入默认路径。
            if (currentDict === undefined) {
              next = updatePayloadValue(next, domainDictPath, '');
            }
            if (currentFileLeakDict === undefined) {
              next = updatePayloadValue(next, fileLeakDictPath, '');
            }
          }
          return next;
        });
      } catch (err: any) {
        if (cancelled) return;
        setTaskDomainDictOptions([]);
        setTaskDefaultDomainDictPath('');
        setTaskFileLeakDictOptions([]);
        setTaskDefaultFileLeakDictPath('');
        setTaskDomainDictError(err?.message || '加载字典列表失败');
        setTaskFileLeakDictError(err?.message || '加载字典列表失败');
      } finally {
        if (!cancelled) setTaskDomainDictLoading(false);
      }
    };

    void loadTaskDomainDictOptions();
    return () => {
      cancelled = true;
    };
  }, [isPolicyAction, isTaskCreate, policyRootPath, shouldLoadDictOptions, token]);

  useEffect(() => {
    if (!shouldLoadPolicyOptions) {
      setTaskSchedulePolicyOptions([]);
      setTaskSchedulePolicyLoading(false);
      setTaskSchedulePolicyError('');
      return;
    }
    let cancelled = false;

    const loadTaskSchedulePolicies = async () => {
      setTaskSchedulePolicyLoading(true);
      setTaskSchedulePolicyError('');
      try {
        const response = await requestApi(token, '/policy/', {
          method: 'GET',
          query: { page: 1, size: 1000, order: 'name' },
        });
        const items = normalizeListData(response).items || [];
        const options = items
          .map((item: any) => {
            const policyId = String(item?._id || item?.policy_id || '').trim();
            const policyName = String(item?.name || '').trim() || '未命名策略';
            if (!policyId) return null;
            return { label: policyName, value: policyId };
          })
          .filter((item): item is { label: string; value: string } => Boolean(item));
        if (cancelled) return;

        setTaskSchedulePolicyOptions(options);
        if (options.length === 0) {
          if (isPolicySelectionRequired) {
            setTaskSchedulePolicyError('未找到可用策略，请先在策略配置中创建策略');
          } else {
            setTaskSchedulePolicyError('');
          }
        } else {
          setTaskSchedulePolicyError('');
          if (!isPolicySelectionRequired) return;
          setFormPayload((prev) => {
            const currentPolicyId = String(prev?.policy_id || '').trim();
            if (currentPolicyId) return prev;
            return updatePayloadValue(prev, 'policy_id', options[0].value);
          });
        }
      } catch (err: any) {
        if (cancelled) return;
        setTaskSchedulePolicyOptions([]);
        if (isPolicySelectionRequired) {
          setTaskSchedulePolicyError(err?.message || '加载策略列表失败');
        } else {
          setTaskSchedulePolicyError('');
        }
      } finally {
        if (!cancelled) {
          setTaskSchedulePolicyLoading(false);
        }
      }
    };

    void loadTaskSchedulePolicies();
    return () => {
      cancelled = true;
    };
  }, [isPolicySelectionRequired, shouldLoadPolicyOptions, token]);

  useEffect(() => {
    if (!isPolicyAction) return;
    let cancelled = false;

    const loadPolicyPlugins = async () => {
      setPolicyPluginLoading(true);
      setPolicyPluginError('');
      try {
        const response = await requestApi(token, '/poc/', {
          method: 'GET',
          query: { page: 1, size: 5000 },
        });
        const items = normalizeListData(response).items || [];
        const normalized = items
          .map((item: any) => ({
            plugin_name: String(item?.plugin_name || '').trim(),
            vul_name: String(item?.vul_name || '').trim(),
            plugin_type: String(item?.plugin_type || '').trim().toLowerCase(),
          }))
          .filter((item: any) => item.plugin_name);
        if (cancelled) return;
        setPolicyPocOptions(
          normalized
            .filter((item: any) => item.plugin_type === 'poc')
            .map((item: any) => ({ plugin_name: item.plugin_name, vul_name: item.vul_name }))
        );
        setPolicyBruteOptions(
          normalized
            .filter((item: any) => item.plugin_type === 'brute')
            .map((item: any) => ({ plugin_name: item.plugin_name, vul_name: item.vul_name }))
        );
      } catch (err: any) {
        if (cancelled) return;
        setPolicyPluginError(err?.message || '加载 PoC 列表失败');
      } finally {
        if (!cancelled) {
          setPolicyPluginLoading(false);
        }
      }
    };

    void loadPolicyPlugins();
    return () => {
      cancelled = true;
    };
  }, [isPolicyAction, token]);

  useEffect(() => {
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
      <div className={`w-full ${isTaskCreate || isPolicyAction || isTaskScheduleCreate ? 'max-w-5xl' : 'max-w-3xl'} bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden`}>
        <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between">
          <div>
            <h4 className="text-lg font-black">{action.label}</h4>
            <p className="text-xs text-brand-text-muted font-mono mt-1">
              {action.method} {action.path}
            </p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-brand-bg/70 transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {action.description ? <p className="text-sm text-brand-text-muted">{action.description}</p> : null}

          {action.fileFieldName ? (
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wider font-bold text-brand-text-muted">上传文件</label>
              <input
                type="file"
                accept={action.fileAccept}
                onChange={(event) => {
                  const nextFile = event.target.files?.[0] || null;
                  setFile(nextFile);
                }}
                className="w-full text-sm file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border file:border-brand-border file:bg-brand-bg file:text-white"
              />
            </div>
          ) : null}

          {isTaskCreate ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">任务名称</label>
                <input
                  value={taskName}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="例如：生产资产扫描-03"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">域名爆破字典</label>
                <div className="relative">
                  <select
                    value={taskDomainDict}
                    disabled={!editable || taskDomainDictLoading}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'domain_dict', event.target.value))}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    {taskDomainDictSelectOptions.length === 0 ? <option value="">暂无可用字典</option> : null}
                    {taskDomainDictSelectOptions.map((item) => (
                      <option key={item.path} value={item.path}>
                        {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
                <p className="text-[11px] text-brand-text-muted">
                  默认自动选择 `domain_2w.txt`；你可以按任务改选其它字典。当前默认：
                  {taskDefaultDomainDictPath ? ` ${taskDefaultDomainDictPath}` : '（未找到，需手动选择）'}
                </p>
              </div>

              {taskDomainDictError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {taskDomainDictError}
                </div>
              ) : null}

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">敏感文件泄漏字典</label>
                <div className="relative">
                  <select
                    value={taskFileLeakDict}
                    disabled={!editable || taskDomainDictLoading}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'file_leak_dict', event.target.value))}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    {taskFileLeakDictSelectOptions.length === 0 ? <option value="">暂无可用字典</option> : null}
                    {taskFileLeakDictSelectOptions.map((item) => (
                      <option key={item.path} value={item.path}>
                        {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
                <p className="text-[11px] text-brand-text-muted">
                  默认使用配置管理中的敏感文件泄漏字典；你可以按任务改选其它字典。当前默认：
                  {taskDefaultFileLeakDictPath ? ` ${taskDefaultFileLeakDictPath}` : '（未找到，需手动选择）'}
                </p>
              </div>

              {taskFileLeakDictError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {taskFileLeakDictError}
                </div>
              ) : null}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">目标（支持一行一个）</label>
                  <textarea
                    value={taskTarget}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'target', event.target.value))}
                    className="w-full min-h-[132px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                    placeholder={'example.com\napi.example.com\n1.2.3.4'}
                  />
                  <p className="text-[11px] text-brand-text-muted">可输入多个目标，支持换行、空格或逗号分隔，提交时会自动归一化。</p>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">端口扫描范围</label>
                  <div className="relative">
                    <select
                      value={taskPortScanType}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'port_scan_type', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="test">test（常见端口）</option>
                      <option value="top100">top100</option>
                      <option value="top1000">top1000</option>
                      <option value="all">all（全端口）</option>
                      <option value="custom">custom（自定义）</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                  {taskPortScanType === 'custom' ? (
                    <input
                      value={taskPortCustom}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'port_custom', event.target.value))}
                      className="mt-2 w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                      placeholder="例如：80,443,8080,10000-10100"
                    />
                  ) : null}
                  <div className="mt-3 p-3 rounded-xl border border-brand-border bg-brand-bg/40 text-[11px] text-brand-text-muted leading-relaxed">
                    建议仅勾选需要的扫描项。目标多时优先开启核心能力（端口扫描、服务识别、站点识别），可提升效率。
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <label className="text-xs font-bold text-brand-text-muted">扫描功能</label>
                  <button
                    type="button"
                    onClick={() => setAllTaskFeatures(!allTaskFeaturesEnabled)}
                    className="text-xs font-bold text-brand-accent hover:underline"
                    disabled={!editable || taskFeatureKeys.length === 0}
                  >
                    {allTaskFeaturesEnabled ? '取消全选' : '全选'}
                  </button>
                </div>
                <div className="space-y-3">
                  {taskFeatureSections.map((section) => (
                    <div key={section.title} className="space-y-2">
                      <p className="text-[11px] font-bold text-brand-text-muted tracking-wide">{section.title}</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                        {section.keys.map((fieldKey) => (
                          <label
                            key={fieldKey}
                            className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm hover:border-brand-accent/50 transition"
                          >
                            <input
                              type="checkbox"
                              checked={Boolean(formPayload?.[fieldKey])}
                              disabled={!editable}
                              className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                              onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, fieldKey, event.target.checked))}
                            />
                            <span className="font-medium truncate">{humanizeField(fieldKey)}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : isFofaAction ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              {isFofaSubmitAction ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">任务名称</label>
                  <input
                    value={fofaTaskName}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                    placeholder="请输入任务名称"
                  />
                </div>
              ) : null}

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">查询语句</label>
                <textarea
                  value={fofaQueryText}
                  disabled={!editable}
                  onChange={(event) => {
                    setFormPayload((prev) => updatePayloadValue(prev, 'query', event.target.value));
                    setFofaResultSize(null);
                  }}
                  className="w-full min-h-[160px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder={'请输入查询语句（支持多行输入）\napp="Nginx"\ncountry="CN" && port="443"'}
                />
                <p className="text-[11px] text-brand-text-muted">
                  一行一条 FOFA 语句，测试和提交时会自动去除空行并去重。
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">结果数</label>
                  <div className="w-full rounded-xl border border-brand-border bg-brand-bg/60 px-3 py-2 text-sm font-mono">
                    {fofaResultSize === null ? '-' : String(fofaResultSize)}
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">测试</label>
                  <button
                    type="button"
                    onClick={() => void runFofaQueryTest()}
                    disabled={!editable || fofaTesting}
                    className="w-full px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition disabled:opacity-60 flex items-center justify-center gap-2"
                  >
                    <Play className={`w-4 h-4 ${fofaTesting ? 'animate-spin' : ''}`} />
                    {fofaTesting ? '测试中...' : '测试'}
                  </button>
                </div>
              </div>

              {isFofaSubmitAction ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">关联策略</label>
                  <div className="relative">
                    <select
                      value={fofaPolicyId}
                      disabled={!editable || taskSchedulePolicyLoading}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'policy_id', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="">
                        {taskSchedulePolicyLoading ? '策略加载中...' : '不关联策略（使用默认扫描配置）'}
                      </option>
                      {taskSchedulePolicyOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              ) : null}
            </div>
          ) : isTaskScheduleCreate ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-brand-text-muted">名称</label>
                  <input
                    value={taskScheduleName}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                    placeholder="请输入计划任务名称"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-brand-text-muted">策略</label>
                  <div className="relative">
                    <select
                      value={taskSchedulePolicyId}
                      disabled={!editable || taskSchedulePolicyLoading}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'policy_id', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="">{taskSchedulePolicyLoading ? '策略加载中...' : '请选择策略'}</option>
                      {taskSchedulePolicyOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-brand-text-muted">计划类型</label>
                  <div className="relative">
                    <select
                      value={taskScheduleType}
                      disabled={!editable}
                      onChange={(event) => {
                        const nextType = event.target.value === 'recurrent_scan' ? 'recurrent_scan' : 'future_scan';
                        setFormPayload((prev) => {
                          let next = updatePayloadValue(prev, 'schedule_type', nextType);
                          if (nextType === 'recurrent_scan' && !String(getPayloadValue(next, 'cron') || '').trim()) {
                            next = updatePayloadValue(next, 'cron', '0 2 * * *');
                          }
                          return next;
                        });
                      }}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="future_scan">定时任务</option>
                      <option value="recurrent_scan">周期任务</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-brand-text-muted">任务类别</label>
                  <div className="relative">
                    <select
                      value={taskScheduleTag}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'task_tag', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="task">资产发现任务</option>
                      <option value="risk_cruising">风险巡航任务</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>

              {taskScheduleType === 'future_scan' ? (
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-brand-text-muted">开始时间</label>
                  <input
                    type="datetime-local"
                    value={taskScheduleStartDate}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'start_date', fromDatetimeLocalValue(event.target.value)))}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  />
                </div>
              ) : (
                <div className="space-y-1">
                  <label className="text-sm font-semibold text-brand-text-muted">CRON</label>
                  <input
                    value={taskScheduleCron}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'cron', event.target.value))}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                    placeholder="例如：0 */6 * * *"
                  />
                </div>
              )}

              <div className="space-y-1">
                <label className="text-sm font-semibold text-brand-text-muted">目标（支持多行，一行一个目标资产）</label>
                <textarea
                  value={taskScheduleTarget}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'target', event.target.value))}
                  className="w-full min-h-[148px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder={
                    taskScheduleTag === 'risk_cruising'
                      ? 'http://10.0.1.1:8081/\n10.0.1.1:2222'
                      : 'example.com\n10.0.0.1\n10.0.0.0/24'
                  }
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm hover:border-brand-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={taskScheduleNotifyEnable}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'notify_enable', event.target.checked))}
                  />
                  <span className="font-medium">钉钉通知</span>
                </label>
                <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm hover:border-brand-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={taskScheduleNotifyKbEnable}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'notify_kb_enable', event.target.checked))}
                  />
                  <span className="font-medium">推送钉钉知识库</span>
                </label>
              </div>

              {taskSchedulePolicyError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {taskSchedulePolicyError}
                </div>
              ) : null}
            </div>
          ) : isGithubSchedulerAction ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-sm font-semibold text-brand-text-muted">任务名</label>
                <input
                  value={githubSchedulerName}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="请输入任务名"
                />
              </div>

              <div className="space-y-1">
                <label className="text-sm font-semibold text-brand-text-muted">关键字</label>
                <input
                  value={githubSchedulerKeyword}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'keyword', event.target.value))}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder="例如：AKIA"
                />
              </div>

              <div className="space-y-1">
                <label className="text-sm font-semibold text-brand-text-muted">cron表达式</label>
                <input
                  value={githubSchedulerCron}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'cron', event.target.value))}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder="例如：0 */6 * * *"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm hover:border-brand-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={githubSchedulerDingdingNotify}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'dingding_notify', event.target.checked))}
                  />
                  <span className="font-medium">钉钉通知</span>
                </label>
                <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm hover:border-brand-accent/50 transition">
                  <input
                    type="checkbox"
                    checked={githubSchedulerKbNotifyEnable}
                    disabled={!editable}
                    className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'kb_notify_enable', event.target.checked))}
                  />
                  <span className="font-medium">推送钉钉知识库</span>
                </label>
              </div>
            </div>
          ) : isAssetScopeCreate ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">资产类别</label>
                <div className="relative">
                  <select
                    value={scopeType}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'scope_type', event.target.value))}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    <option value="domain">域名资产</option>
                    <option value="ip">IP资产</option>
                  </select>
                  <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">资产组名称</label>
                <input
                  value={scopeGroupName}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'name', event.target.value))}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="例如：生产外网资产"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">资产范围（支持一行一个）</label>
                <textarea
                  value={scopeText}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'scope', event.target.value))}
                  className="w-full min-h-[168px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder={
                    scopeType === 'ip'
                      ? '1.1.1.1\n1.1.1.0/24\n1.1.1.1-1.1.1.100'
                      : 'example.com\napi.example.com'
                  }
                />
                <p className="text-[11px] text-brand-text-muted">
                  支持换行、空格或逗号分隔，提交时会自动归一化为多条资产范围。
                </p>
              </div>
            </div>
          ) : isAssetScopeAddScope ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">资产组名称</label>
                <input
                  value={scopeGroupName}
                  disabled
                  className="w-full rounded-xl border border-brand-border bg-brand-bg/60 px-3 py-2 text-sm"
                  placeholder="取资产组名称"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">资产范围</label>
                <textarea
                  value={scopeAddTargetText}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'scope', event.target.value))}
                  className="w-full min-h-[168px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder={'example.com\napi.example.com'}
                />
                <p className="text-[11px] text-brand-text-muted">支持多行或逗号分割。</p>
              </div>
            </div>
          ) : isAssetScopeAddScheduler ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">范围</label>
                <textarea
                  value={scopeMonitorRangeText}
                  disabled={!editable}
                  onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'domain', event.target.value))}
                  className="w-full min-h-[148px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder={'example.com\napi.example.com'}
                />
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">运行间隔</label>
                  <div className="relative">
                    <input
                      type="number"
                      min={6}
                      value={scopeMonitorIntervalHours}
                      disabled={!editable}
                      onChange={(event) => {
                        const nextHours = Number(event.target.value || '0');
                        const safeHours = Number.isFinite(nextHours) ? Math.max(1, Math.floor(nextHours)) : 1;
                        setFormPayload((prev) => updatePayloadValue(prev, 'interval', safeHours * 3600));
                      }}
                      className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 pr-10 text-sm"
                    />
                    <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-brand-text-muted">小时</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">策略</label>
                  <div className="relative">
                    <select
                      value={taskSchedulePolicyId}
                      disabled={!editable || taskSchedulePolicyLoading}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'policy_id', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="">{taskSchedulePolicyLoading ? '策略加载中...' : '请选择策略'}</option>
                      {taskSchedulePolicyOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>
              {taskSchedulePolicyError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {taskSchedulePolicyError}
                </div>
              ) : null}
            </div>
          ) : (isAssetScopeAddSiteMonitor || isAssetScopeAddWihMonitor) ? (
            <div className="space-y-4 max-h-[56vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">运行间隔</label>
                <div className="relative">
                  <input
                    type="number"
                    min={6}
                    value={scopeMonitorIntervalHours}
                    disabled={!editable}
                    onChange={(event) => {
                      const nextHours = Number(event.target.value || '0');
                      const safeHours = Number.isFinite(nextHours) ? Math.max(1, Math.floor(nextHours)) : 1;
                      setFormPayload((prev) => updatePayloadValue(prev, 'interval', safeHours * 3600));
                    }}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 pr-10 text-sm"
                  />
                  <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-brand-text-muted">小时</span>
                </div>
              </div>
            </div>
          ) : isPolicyAction ? (
            <div className="space-y-5 max-h-[62vh] overflow-y-auto custom-scrollbar pr-1">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">策略名称</label>
                  <input
                    value={policyName}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, policyNamePath, event.target.value))}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                    placeholder="请输入策略名称"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">策略描述</label>
                  <input
                    value={policyDesc}
                    disabled={!editable}
                    onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, policyDescPath, event.target.value))}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                    placeholder="请输入策略描述"
                  />
                </div>
              </div>

              <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
                <h5 className="text-sm font-black">字典配置</h5>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-brand-text-muted">域名爆破字典</label>
                    <div className="relative">
                      <select
                        value={policyDomainDict}
                        disabled={!editable || taskDomainDictLoading}
                        onChange={(event) => updatePolicyValue('domain_dict', event.target.value)}
                        className={UNIFIED_SELECT_CLASS}
                      >
                        <option value="">跟随配置管理默认字典</option>
                        {policyDomainDictSelectOptions.map((item) => (
                          <option key={item.path} value={item.path}>
                            {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                          </option>
                        ))}
                      </select>
                      <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                    <p className="text-[11px] text-brand-text-muted">
                      不选择时，按配置管理默认字典执行。当前默认：
                      {taskDefaultDomainDictPath ? ` ${taskDefaultDomainDictPath}` : '（未配置）'}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-brand-text-muted">敏感文件泄漏字典</label>
                    <div className="relative">
                      <select
                        value={policyFileLeakDict}
                        disabled={!editable || taskDomainDictLoading}
                        onChange={(event) => updatePolicyValue('file_leak_dict', event.target.value)}
                        className={UNIFIED_SELECT_CLASS}
                      >
                        <option value="">跟随配置管理默认字典</option>
                        {policyFileLeakDictSelectOptions.map((item) => (
                          <option key={item.path} value={item.path}>
                            {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                          </option>
                        ))}
                      </select>
                      <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                    <p className="text-[11px] text-brand-text-muted">
                      不选择时，按配置管理默认字典执行。当前默认：
                      {taskDefaultFileLeakDictPath ? ` ${taskDefaultFileLeakDictPath}` : '（未配置）'}
                    </p>
                  </div>
                </div>
              </div>

              {taskDomainDictError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {taskDomainDictError}
                </div>
              ) : null}
              {taskFileLeakDictError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {taskFileLeakDictError}
                </div>
              ) : null}

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">端口扫描类型</label>
                <div className="relative">
                  <select
                    value={policyPortScanType}
                    disabled={!editable}
                    onChange={(event) => updatePolicyValue('ip_config.port_scan_type', event.target.value)}
                    className={UNIFIED_SELECT_CLASS}
                  >
                    <option value="test">测试</option>
                    <option value="top100">TOP100</option>
                    <option value="top1000">TOP1000</option>
                    <option value="all">全端口</option>
                    <option value="custom">自定义</option>
                  </select>
                  <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              {policyPortScanType === 'custom' ? (
                <div className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">自定义端口</label>
                  <input
                    value={policyPortCustom}
                    disabled={!editable}
                    onChange={(event) => updatePolicyValue('ip_config.port_custom', event.target.value)}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                    placeholder="80,443,8080"
                  />
                </div>
              ) : null}

              <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h5 className="text-sm font-black">站点和风险配置</h5>
                  <button
                    type="button"
                    className="text-xs font-bold text-brand-accent hover:underline"
                    onClick={() => setPolicySiteOptionAll(!policySiteOptionAllEnabled)}
                    disabled={!editable}
                  >
                    {policySiteOptionAllEnabled ? '取消全选' : '全选'}
                  </button>
                </div>
                <input
                  value={policySearchKeyword}
                  onChange={(event) => setPolicySearchKeyword(event.target.value)}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="请输入关键字进行查询"
                />
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                  {filteredPolicySiteOptions.map((item) => (
                    <label key={item.key} className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={Boolean(getPayloadValue(formPayload, getPolicyPath(item.key)))}
                        disabled={!editable}
                        onChange={(event) => updatePolicyValue(item.key, event.target.checked)}
                        className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                      />
                      <span className="truncate">{item.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h5 className="text-sm font-black">PoC 配置</h5>
                  <button
                    type="button"
                    className="text-xs font-bold text-brand-accent hover:underline"
                    onClick={() =>
                      setPolicyPluginConfig(
                        'poc_config',
                        policyPocAllSelected ? [] : policyPocOptions.map((item) => item.plugin_name)
                      )
                    }
                    disabled={!editable || policyPocOptions.length === 0}
                  >
                    {policyPocAllSelected ? '取消全选' : '全选'}
                  </button>
                </div>
                <input
                  value={policyPocKeyword}
                  onChange={(event) => setPolicyPocKeyword(event.target.value)}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="请输入关键字筛选 PoC"
                />
                <div className="max-h-52 overflow-y-auto custom-scrollbar grid grid-cols-1 md:grid-cols-2 gap-2 pr-1">
                  {filteredPolicyPocOptions.map((item) => (
                    <label key={item.plugin_name} className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={selectedPolicyPocNames.includes(item.plugin_name)}
                        disabled={!editable}
                        onChange={(event) => togglePolicyPluginSelection('poc_config', item.plugin_name, event.target.checked)}
                        className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                      />
                      <span className="truncate">{item.vul_name || item.plugin_name}</span>
                    </label>
                  ))}
                  {!policyPluginLoading && filteredPolicyPocOptions.length === 0 ? (
                    <p className="text-xs text-brand-text-muted">暂无匹配的 PoC 项</p>
                  ) : null}
                </div>
              </div>

              <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h5 className="text-sm font-black">弱口令爆破配置</h5>
                  <button
                    type="button"
                    className="text-xs font-bold text-brand-accent hover:underline"
                    onClick={() =>
                      setPolicyPluginConfig(
                        'brute_config',
                        policyBruteAllSelected ? [] : policyBruteOptions.map((item) => item.plugin_name)
                      )
                    }
                    disabled={!editable || policyBruteOptions.length === 0}
                  >
                    {policyBruteAllSelected ? '取消全选' : '全选'}
                  </button>
                </div>
                <input
                  value={policyBruteKeyword}
                  onChange={(event) => setPolicyBruteKeyword(event.target.value)}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="请输入关键字筛选弱口令插件"
                />
                <div className="max-h-52 overflow-y-auto custom-scrollbar grid grid-cols-1 md:grid-cols-2 gap-2 pr-1">
                  {filteredPolicyBruteOptions.map((item) => (
                    <label key={item.plugin_name} className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={selectedPolicyBruteNames.includes(item.plugin_name)}
                        disabled={!editable}
                        onChange={(event) => togglePolicyPluginSelection('brute_config', item.plugin_name, event.target.checked)}
                        className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                      />
                      <span className="truncate">{item.vul_name || item.plugin_name}</span>
                    </label>
                  ))}
                  {!policyPluginLoading && filteredPolicyBruteOptions.length === 0 ? (
                    <p className="text-xs text-brand-text-muted">暂无匹配的弱口令插件</p>
                  ) : null}
                </div>
              </div>

              {policyPluginLoading ? (
                <div className="text-xs text-brand-text-muted">PoC 列表加载中...</div>
              ) : null}
              {policyPluginError ? (
                <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">
                  {policyPluginError}
                </div>
              ) : null}
            </div>
          ) : (
            <div className="space-y-3 max-h-[52vh] overflow-y-auto custom-scrollbar pr-1">
              {displayFields.map((field) => {
                const value = field.value;
                const disabled = !editable;
                const isBoolean = typeof value === 'boolean';
                const isNumber = typeof value === 'number';
                const isComplex = Array.isArray(value) || (value && typeof value === 'object');

                return (
                  <div key={field.path} className="space-y-1">
                    <label className="text-xs font-bold text-brand-text-muted">
                      {humanizeField(field.path)}
                      {!isTaskCreate && !isPolicyAction ? <span className="ml-2 text-[10px] font-mono opacity-70">{field.path}</span> : null}
                    </label>
                    {isBoolean ? (
                      <label className="flex items-center justify-between rounded-xl border border-brand-border bg-brand-bg px-3 py-2.5 text-sm">
                        <span className="font-semibold">{value ? '启用' : '关闭'}</span>
                        <input
                          type="checkbox"
                          checked={value}
                          disabled={disabled}
                          className="h-5 w-5 cursor-pointer rounded-md border border-brand-border bg-brand-bg"
                          onChange={(event) => {
                            setFormPayload((prev) => updatePayloadValue(prev, field.path, event.target.checked));
                          }}
                        />
                      </label>
                    ) : isNumber ? (
                      <input
                        type="number"
                        value={value}
                        disabled={disabled}
                        onChange={(event) => {
                          const next = Number(event.target.value || '0');
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, next));
                        }}
                        className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                      />
                    ) : isComplex ? (
                      <input
                        value={Array.isArray(value) ? value.join(',') : String(value ?? '')}
                        disabled={disabled}
                        onChange={(event) => {
                          const nextValues = event.target.value
                            .split(',')
                            .map((item) => item.trim())
                            .filter((item) => item);
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, nextValues));
                          setError('');
                        }}
                        placeholder="多个值请用逗号分隔"
                        className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                      />
                    ) : (
                      <input
                        value={String(value ?? '')}
                        disabled={disabled}
                        onChange={(event) => {
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, event.target.value));
                        }}
                        className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                      />
                    )}
                  </div>
                );
              })}

            </div>
          )}

          {!editable ? (
            <div className="text-xs text-brand-text-muted bg-brand-bg/60 border border-brand-border rounded-lg px-3 py-2">
              当前动作使用固定参数，已禁用编辑。
            </div>
          ) : null}

          {error ? (
            <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">{error}</div>
          ) : null}

          <div className="flex justify-end gap-3">
            <button
              onClick={onClose}
              className="px-5 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition"
            >
              取消
            </button>
            <button
              onClick={async () => {
                try {
                  setLoading(true);
                  setError('');
                  let payload: JsonValue = deepClone(!editable ? initialPayload : formPayload);
                  if (isFofaAction && editable) {
                    const normalizedQueryList = normalizeFofaQueries(String(payload.query || ''));
                    if (normalizedQueryList.length === 0) {
                      throw new Error('请填写查询语句（支持多行输入）');
                    }

                    const normalizedQuery = normalizedQueryList.join('\n');
                    payload.query = normalizedQuery;

                    if (isFofaSubmitAction) {
                      const normalizedName = String(payload.name || '').trim();
                      const policyId = String(payload.policy_id || '').trim();

                      if (!normalizedName) {
                        throw new Error('请填写任务名称');
                      }

                      payload.name = normalizedName;
                      if (policyId) {
                        payload.policy_id = policyId;
                      } else {
                        delete payload.policy_id;
                      }
                    } else {
                      payload = { query: normalizedQuery };
                    }
                  }
                  if (isTaskCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedTargets = String(payload.target || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .map((item) => item.trim())
                      .filter((item) => item);
                    const normalizedDomainDict = String(payload.domain_dict || '').trim();
                    const fallbackDomainDict = String(taskDefaultDomainDictPath || '').trim();
                    const resolvedDomainDict = normalizedDomainDict || fallbackDomainDict;
                    const normalizedFileLeakDict = String(payload.file_leak_dict || '').trim();
                    const fallbackFileLeakDict = String(taskDefaultFileLeakDictPath || '').trim();
                    const resolvedFileLeakDict = normalizedFileLeakDict || fallbackFileLeakDict;
                    const normalizedPortScanType = String(payload.port_scan_type || 'test').trim().toLowerCase();
                    const normalizedPortCustom = String(payload.port_custom || '')
                      .replace(/，/g, ',')
                      .replace(/\s+/g, ',')
                      .split(',')
                      .map((item) => item.trim())
                      .filter((item) => item)
                      .join(',');

                    if (!normalizedName) {
                      throw new Error('请填写任务名称');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写目标，支持一行一个');
                    }
                    if (normalizedPortScanType === 'custom') {
                      if (!normalizedPortCustom) {
                        throw new Error('端口扫描范围为 custom 时，请填写自定义端口');
                      }
                      const hasInvalidPort = normalizedPortCustom
                        .split(',')
                        .some((item) => !/^\d+(?:-\d+)?$/.test(item));
                      if (hasInvalidPort) {
                        throw new Error('自定义端口格式错误，仅支持端口或端口段，如 80,443,10000-10100');
                      }
                    }

                    payload.name = normalizedName;
                    payload.target = normalizedTargets.join('\n');
                    payload.domain_brute = true;
                    payload.domain_brute_type = 'big';
                    payload.port_scan_type = normalizedPortScanType;
                    if (!resolvedDomainDict) {
                      throw new Error('未找到可用域名爆破字典，请先在配置管理中确认 domain_2w.txt 或上传字典');
                    }
                    payload.domain_dict = resolvedDomainDict;
                    if (Boolean(payload.file_leak) && !resolvedFileLeakDict) {
                      throw new Error('文件泄漏已开启，但未找到可用敏感文件泄漏字典，请先在配置管理中配置或上传字典');
                    }
                    if (resolvedFileLeakDict) {
                      payload.file_leak_dict = resolvedFileLeakDict;
                    } else {
                      delete payload.file_leak_dict;
                    }
                    if (normalizedPortScanType === 'custom') {
                      payload.port_custom = normalizedPortCustom;
                    } else {
                      delete payload.port_custom;
                    }
                  }
                  if (isTaskScheduleCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedTargets = String(payload.target || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);
                    const scheduleType = String(payload.schedule_type || 'future_scan').trim().toLowerCase();
                    const taskTag = String(payload.task_tag || 'task').trim().toLowerCase();
                    const policyId = String(payload.policy_id || '').trim();
                    const cron = String(payload.cron || '').trim();
                    const startDate = fromDatetimeLocalValue(String(payload.start_date || '').trim());

                    if (!normalizedName) {
                      throw new Error('请填写名称');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写目标，支持一行一个目标资产');
                    }
                    if (!policyId) {
                      throw new Error('请选择策略');
                    }
                    if (!['future_scan', 'recurrent_scan'].includes(scheduleType)) {
                      throw new Error('计划类型无效');
                    }
                    if (!['task', 'risk_cruising'].includes(taskTag)) {
                      throw new Error('任务类别无效');
                    }
                    if (scheduleType === 'future_scan' && !startDate) {
                      throw new Error('请选择开始时间');
                    }
                    if (scheduleType === 'recurrent_scan' && !cron) {
                      throw new Error('请填写 CRON 表达式');
                    }

                    payload.name = normalizedName;
                    payload.target = normalizedTargets.join('\n');
                    payload.schedule_type = scheduleType;
                    payload.task_tag = taskTag;
                    payload.policy_id = policyId;
                    payload.notify_enable = Boolean(payload.notify_enable);
                    payload.notify_kb_enable = Boolean(payload.notify_kb_enable);
                    payload.notify_channel = 'dingding';
                    payload.notify_on = 'finished';
                    if (scheduleType === 'future_scan') {
                      payload.start_date = startDate;
                      payload.cron = '';
                    } else {
                      payload.cron = cron;
                      payload.start_date = '';
                    }
                  }
                  if (isGithubSchedulerAction && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedKeyword = String(payload.keyword || '').trim();
                    const normalizedCron = String(payload.cron || '').trim();

                    if (!normalizedName) {
                      throw new Error('请填写任务名');
                    }
                    if (!normalizedKeyword) {
                      throw new Error('请填写关键字');
                    }
                    if (!normalizedCron) {
                      throw new Error('请填写 cron 表达式');
                    }

                    payload.name = normalizedName;
                    payload.keyword = normalizedKeyword;
                    payload.cron = normalizedCron;
                    payload.dingding_notify = Boolean(payload.dingding_notify);
                    payload.kb_notify_enable = Boolean(payload.kb_notify_enable);
                  }
                  if (isAssetScopeCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedScopes = String(payload.scope || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!normalizedName) {
                      throw new Error('请填写资产组名称');
                    }
                    if (normalizedScopes.length === 0) {
                      throw new Error('请填写资产范围，支持一行一个');
                    }

                    payload.name = normalizedName;
                    payload.scope_type = String(payload.scope_type || 'domain') === 'ip' ? 'ip' : 'domain';
                    payload.scope = normalizedScopes.join('\n');
                    payload.black_scope = '';
                  }
                  if (isAssetScopeAddScope && editable) {
                    const scopeId = String(payload.scope_id || '').trim();
                    const normalizedScopes = String(payload.scope || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!scopeId) {
                      throw new Error('资产范围ID无效，请刷新后重试');
                    }
                    if (normalizedScopes.length === 0) {
                      throw new Error('请填写资产范围，支持多行或逗号分割');
                    }

                    payload = {
                      scope_id: scopeId,
                      scope: normalizedScopes.join(','),
                    };
                  }
                  if (isAssetScopeAddScheduler && editable) {
                    const scopeId = String(payload.scope_id || '').trim();
                    const policyId = String(payload.policy_id || '').trim();
                    const normalizedName = String(payload.name || '').trim();
                    const interval = Number(payload.interval || 0);
                    const normalizedTargets = String(payload.domain || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .flatMap((line) => line.split(/\s+/))
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!scopeId) {
                      throw new Error('资产范围ID无效，请刷新后重试');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写范围');
                    }
                    if (!Number.isFinite(interval) || interval < 3600 * 6) {
                      throw new Error('运行间隔最小为6小时');
                    }

                    payload = {
                      scope_id: scopeId,
                      domain: normalizedTargets.join(','),
                      interval: Math.floor(interval),
                      name: normalizedName,
                      policy_id: policyId,
                    };
                  }
                  if ((isAssetScopeAddSiteMonitor || isAssetScopeAddWihMonitor) && editable) {
                    const scopeId = String(payload.scope_id || '').trim();
                    const normalizedName = String(payload.name || '').trim();
                    const interval = Number(payload.interval || 0);

                    if (!scopeId) {
                      throw new Error('资产范围ID无效，请刷新后重试');
                    }
                    if (!Number.isFinite(interval) || interval < 3600 * 6) {
                      throw new Error('运行间隔最小为6小时');
                    }

                    payload = {
                      scope_id: scopeId,
                      interval: Math.floor(interval),
                      name: normalizedName,
                    };
                  }
                  if (isPolicyAction && editable) {
                    const normalizedPolicyName = String(getPayloadValue(payload, policyNamePath) || '').trim();
                    if (!normalizedPolicyName) {
                      throw new Error('请填写策略名称');
                    }

                    const normalizedPortScanType = String(getPayloadValue(payload, getPolicyPath('ip_config.port_scan_type')) || 'test').trim().toLowerCase();
                    const normalizedPortCustom = String(getPayloadValue(payload, getPolicyPath('ip_config.port_custom')) || '')
                      .replace(/，/g, ',')
                      .replace(/\s+/g, ',')
                      .split(',')
                      .map((item) => item.trim())
                      .filter((item) => item)
                      .join(',');
                    const normalizedDomainDict = String(getPayloadValue(payload, getPolicyPath('domain_dict')) || '').trim();
                    const normalizedFileLeakDict = String(getPayloadValue(payload, getPolicyPath('file_leak_dict')) || '').trim();

                    if (normalizedPortScanType === 'custom' && !normalizedPortCustom) {
                      throw new Error('端口扫描类型为自定义时，请填写自定义端口');
                    }
                    if (normalizedPortScanType === 'custom') {
                      const hasInvalidPort = normalizedPortCustom
                        .split(',')
                        .some((item) => !/^\d+(?:-\d+)?$/.test(item));
                      if (hasInvalidPort) {
                        throw new Error('自定义端口格式错误，仅支持端口或端口段，如 80,443,10000-10100');
                      }
                    }

                    payload = updatePayloadValue(payload, policyNamePath, normalizedPolicyName);
                    // 策略层固定启用域名爆破，字典来源通过 domain_dict 指定。
                    payload = updatePayloadValue(payload, getPolicyPath('domain_config.domain_brute'), true);
                    payload = updatePayloadValue(payload, getPolicyPath('domain_config.domain_brute_type'), 'big');
                    payload = updatePayloadValue(payload, getPolicyPath('domain_dict'), normalizedDomainDict);
                    payload = updatePayloadValue(payload, getPolicyPath('file_leak_dict'), normalizedFileLeakDict);
                    if (normalizedPortScanType === 'custom') {
                      payload = updatePayloadValue(payload, getPolicyPath('ip_config.port_custom'), normalizedPortCustom);
                    }
                  }
                  await onSubmit(payload, file);
                  onClose();
                } catch (err: any) {
                  setError(err?.message || '执行失败');
                } finally {
                  setLoading(false);
                }
              }}
              className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider uppercase"
              disabled={loading}
            >
              {loading ? '执行中...' : (isPolicyAction || isTaskScheduleCreate || isGithubSchedulerAction || isAssetScopeAddScope || isAssetScopeAddScheduler || isAssetScopeAddSiteMonitor || isAssetScopeAddWihMonitor) ? '确定' : '执行'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function TableModuleView({
  module,
  token,
  onOpenModule,
  externalFilters,
  onClearExternalFilters,
}: {
  module: ModuleConfig;
  token: string;
  onOpenModule: (moduleId: string, nextFilters?: JsonValue) => void;
  externalFilters?: JsonValue;
  onClearExternalFilters?: () => void;
}) {
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const [order, setOrder] = useState(module.defaultOrder || '');
  const [total, setTotal] = useState(0);
  const [quickFilter, setQuickFilter] = useState('');
  const [taskNameViewInput, setTaskNameViewInput] = useState('');
  const [searchForm, setSearchForm] = useState<JsonValue>({});
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [dialogAction, setDialogAction] = useState<ModuleAction | null>(null);
  const [dialogPayload, setDialogPayload] = useState<JsonValue>({});
  const [riskDialogOpen, setRiskDialogOpen] = useState(false);
  const [riskDialogLoading, setRiskDialogLoading] = useState(false);
  const [riskDialogSubmitting, setRiskDialogSubmitting] = useState(false);
  const [riskDialogError, setRiskDialogError] = useState('');
  const [riskPolicies, setRiskPolicies] = useState<Array<{ policyId: string; policyName: string; pocCount: number }>>([]);
  const [riskPolicyId, setRiskPolicyId] = useState('');
  const [riskTaskName, setRiskTaskName] = useState('');
  const [riskResultSetId, setRiskResultSetId] = useState('');
  const [riskResultTotal, setRiskResultTotal] = useState(0);
  const [policyTaskDialogOpen, setPolicyTaskDialogOpen] = useState(false);
  const [policyTaskSubmitting, setPolicyTaskSubmitting] = useState(false);
  const [policyTaskError, setPolicyTaskError] = useState('');
  const [policyTaskPolicyId, setPolicyTaskPolicyId] = useState('');
  const [policyTaskPolicyName, setPolicyTaskPolicyName] = useState('');
  const [policyTaskTag, setPolicyTaskTag] = useState<'task' | 'risk_cruising'>('task');
  const [policyTaskName, setPolicyTaskName] = useState('');
  const [policyTaskTarget, setPolicyTaskTarget] = useState('');
  const [taskSchedulePolicyOptions, setTaskSchedulePolicyOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [taskDetailCounts, setTaskDetailCounts] = useState<Record<string, number>>({});
  const [taskDetailCountLoading, setTaskDetailCountLoading] = useState(false);
  const [expandedScopeRows, setExpandedScopeRows] = useState<Record<string, boolean>>({});
  const [expandedTaskScheduleTargetRows, setExpandedTaskScheduleTargetRows] = useState<Record<string, boolean>>({});
  const [expandedTaskOptionRows, setExpandedTaskOptionRows] = useState<Record<string, boolean>>({});
  const [taskCompactMode, setTaskCompactMode] = useState(true);
  const [taskErrorDialog, setTaskErrorDialog] = useState<{
    taskId: string;
    taskName: string;
    target: string;
    logs: Array<{
      time: string;
      stage: string;
      message: string;
      traceback: string;
    }>;
  } | null>(null);
  const [screenshotPreview, setScreenshotPreview] = useState<{ url: string; title: string } | null>(null);
  const [deleteConfirmDialog, setDeleteConfirmDialog] = useState<{
    title: string;
    message: string;
    confirmText: string;
  } | null>(null);
  const deleteConfirmResolverRef = useRef<((confirmed: boolean) => void) | null>(null);
  const activeExternalFilters = useMemo(
    () => (externalFilters && Object.keys(externalFilters).length > 0 ? externalFilters : {}),
    [externalFilters]
  );
  const hasExternalFilters = useMemo(() => Object.keys(activeExternalFilters).length > 0, [activeExternalFilters]);

  const hasList = Boolean(module.listPath);
  const hasAdvancedSearch = Array.isArray(module.searchFields) && module.searchFields.length > 0;

  const normalizeTaskErrorLog = useCallback((raw: any) => {
    if (!raw || typeof raw !== 'object') return null;
    const time = sanitizeUiMessage(String(raw?.time || '').trim(), 80) || '-';
    const stage = sanitizeUiMessage(String(raw?.stage || '').trim(), 120) || '-';
    const message = sanitizeUiMessage(String(raw?.message || '').trim(), 3000) || '未知异常';
    const traceback = sanitizeUiMessage(String(raw?.traceback || '').trim(), 12000) || '';
    return { time, stage, message, traceback };
  }, []);

  const buildTaskErrorLogs = useCallback((row: any) => {
    const logs: Array<{ time: string; stage: string; message: string; traceback: string }> = [];
    if (Array.isArray(row?.error_logs)) {
      row.error_logs.forEach((item: any) => {
        const normalized = normalizeTaskErrorLog(item);
        if (normalized) logs.push(normalized);
      });
    }

    const lastError = normalizeTaskErrorLog(row?.last_error);
    if (lastError) logs.push(lastError);

    if (logs.length === 0) {
      const fallbackMessage =
        sanitizeUiMessage(String(row?.error || row?.error_msg || row?.message || '').trim(), 3000) || '';
      if (fallbackMessage) {
        logs.push({
          time: '-',
          stage: '-',
          message: fallbackMessage,
          traceback: '',
        });
      }
    }

    const uniqMap = new Map<string, { time: string; stage: string; message: string; traceback: string }>();
    logs.forEach((item) => {
      const key = `${item.time}|${item.stage}|${item.message}|${item.traceback}`;
      if (!uniqMap.has(key)) uniqMap.set(key, item);
    });

    return Array.from(uniqMap.values());
  }, [normalizeTaskErrorLog]);

  const openTaskErrorDialog = useCallback((row: any) => {
    const taskId = String(row?._id || row?.task_id || '').trim();
    const taskName = sanitizeUiMessage(String(row?.name || '').trim(), 200) || '-';
    const target = sanitizeUiMessage(String(row?.target || '').trim(), 500) || '-';
    const logs = buildTaskErrorLogs(row);
    setTaskErrorDialog({
      taskId,
      taskName,
      target,
      logs,
    });
  }, [buildTaskErrorLogs]);

  useEffect(() => {
    if (!hasAdvancedSearch) {
      setSearchForm({});
      return;
    }
    const next: JsonValue = {};
    (module.searchFields || []).forEach((field) => {
      next[field.key] = '';
    });
    setSearchForm(next);
  }, [module.id, hasAdvancedSearch, module.searchFields]);

  useEffect(() => {
    setOrder(module.defaultOrder || '');
  }, [module.id, module.defaultOrder]);

  useEffect(() => {
    setRiskDialogOpen(false);
    setRiskDialogError('');
    setRiskDialogLoading(false);
    setRiskDialogSubmitting(false);
    setPolicyTaskDialogOpen(false);
    setPolicyTaskSubmitting(false);
    setPolicyTaskError('');
    setExpandedScopeRows({});
    setExpandedTaskScheduleTargetRows({});
    setExpandedTaskOptionRows({});
    setTaskCompactMode(true);
    setTaskNameViewInput('');
    setTaskErrorDialog(null);
    setScreenshotPreview(null);
  }, [module.id]);

  useEffect(() => {
    if (!taskErrorDialog) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setTaskErrorDialog(null);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [taskErrorDialog]);

  useEffect(() => {
    if (!screenshotPreview) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setScreenshotPreview(null);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [screenshotPreview]);

  const closeDeleteConfirmDialog = useCallback((confirmed: boolean) => {
    const resolver = deleteConfirmResolverRef.current;
    deleteConfirmResolverRef.current = null;
    setDeleteConfirmDialog(null);
    if (resolver) resolver(confirmed);
  }, []);

  const askDeleteConfirm = useCallback((message: string, title = '确认删除'): Promise<boolean> => {
    const safeMessage = sanitizeUiMessage(message, 400) || '确认执行删除操作吗？';
    return new Promise((resolve) => {
      deleteConfirmResolverRef.current = resolve;
      setDeleteConfirmDialog({
        title: sanitizeUiMessage(title, 80) || '确认删除',
        message: safeMessage,
        confirmText: '确认删除',
      });
    });
  }, []);

  useEffect(() => {
    if (!deleteConfirmDialog) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      closeDeleteConfirmDialog(false);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [closeDeleteConfirmDialog, deleteConfirmDialog]);

  useEffect(() => () => {
    if (deleteConfirmResolverRef.current) {
      deleteConfirmResolverRef.current(false);
      deleteConfirmResolverRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (module.id !== 'task_schedule') {
      setTaskSchedulePolicyOptions([]);
      return;
    }

    let cancelled = false;
    const loadPolicyOptions = async () => {
      try {
        const response = await requestApi(token, '/policy/', {
          method: 'GET',
          query: { page: 1, size: 1000, order: 'name' },
        });
        const items = normalizeListData(response).items || [];
        const uniqueNames = Array.from(
          new Set(
            items
              .map((item: any) => String(item?.name || '').trim())
              .filter((name: string) => name)
          )
        );
        if (cancelled) return;
        setTaskSchedulePolicyOptions(uniqueNames.map((name) => ({ label: name, value: name })));
      } catch {
        if (cancelled) return;
        setTaskSchedulePolicyOptions([]);
      }
    };

    void loadPolicyOptions();
    return () => {
      cancelled = true;
    };
  }, [module.id, token]);

  const isTaskDetailModule = useMemo(
    () => TASK_DETAIL_TABS.some((tab) => tab.id === module.id),
    [module.id]
  );

  useEffect(() => {
    if (!isTaskDetailModule) {
      setTaskDetailCounts({});
      setTaskDetailCountLoading(false);
      return;
    }

    let cancelled = false;
    const loadTaskDetailCounts = async () => {
      setTaskDetailCountLoading(true);
      try {
        const requests = TASK_DETAIL_TABS.map(async (tab) => {
          const tabModule = getModuleById(tab.id);
          if (!tabModule.listPath) return [tab.id, 0] as const;
          const response = await requestApi(token, tabModule.listPath, {
            method: 'GET',
            query: {
              page: 1,
              size: 1,
              ...activeExternalFilters,
            },
          });
          const normalized = normalizeListData(response);
          return [tab.id, Number(normalized.total || 0)] as const;
        });

        const entries = await Promise.all(requests);
        if (cancelled) return;
        const nextCounts: Record<string, number> = {};
        entries.forEach(([id, count]) => {
          nextCounts[id] = count;
        });
        setTaskDetailCounts(nextCounts);
      } catch {
        if (cancelled) return;
        setTaskDetailCounts({});
      } finally {
        if (!cancelled) setTaskDetailCountLoading(false);
      }
    };

    void loadTaskDetailCounts();
    return () => {
      cancelled = true;
    };
  }, [isTaskDetailModule, token, activeExternalFilters]);

  const getSearchFieldOptions = (field: ModuleSearchField): Array<{ label: string; value: string }> => {
    if (field.dynamicOptionsKey === 'policy_name') {
      return [{ label: '全部策略', value: '' }, ...taskSchedulePolicyOptions];
    }
    if (Array.isArray(field.options)) {
      return field.options;
    }
    return [{ label: '全部', value: '' }];
  };

  const buildFilters = useCallback((): JsonValue => {
    const filters: JsonValue = {};
    if (hasAdvancedSearch) {
      (module.searchFields || []).forEach((field) => {
        const raw = searchForm?.[field.key];
        if (raw === undefined || raw === null) return;
        const text = String(raw).trim();
        if (!text) return;
        if (field.inputType === 'number') {
          const parsed = Number(text);
          if (Number.isFinite(parsed)) {
            filters[field.key] = parsed;
          }
          return;
        }
        filters[field.key] = text;
      });
      return { ...activeExternalFilters, ...filters };
    }
    if (module.quickFilterKey && quickFilter.trim()) {
      filters[module.quickFilterKey] = quickFilter.trim();
    }
    return { ...activeExternalFilters, ...filters };
  }, [activeExternalFilters, hasAdvancedSearch, module.quickFilterKey, module.searchFields, quickFilter, searchForm]);

  const clearSearchFilters = useCallback(() => {
    if (hasAdvancedSearch) {
      const resetForm: JsonValue = {};
      (module.searchFields || []).forEach((field) => {
        resetForm[field.key] = '';
      });
      setSearchForm(resetForm);
    } else {
      setQuickFilter('');
    }
    setPage(1);
  }, [hasAdvancedSearch, module.searchFields]);

  const loadRows = useCallback(async () => {
    if (!module.listPath) return;
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const filters = buildFilters();

      const query: JsonValue = {
        page,
        size,
        ...filters,
      };

      const orderValue = String(order || '').trim();
      if (orderValue) {
        query.order = orderValue;
      } else if (module.defaultOrder && !('order' in query)) {
        query.order = module.defaultOrder;
      }

      const response = await requestApi(token, module.listPath, { method: 'GET', query });
      const normalized = normalizeListData(response);
      setRows(normalized.items);
      setTotal(normalized.total);
      setSelectedIds([]);
    } catch (err: any) {
      setError(err?.message || '加载失败');
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [buildFilters, module.defaultOrder, module.listPath, order, page, size, token]);

  useEffect(() => {
    void loadRows();
  }, [loadRows]);

  const totalPages = Math.max(1, Math.ceil(total / size));

  const columns = useMemo(() => {
    if (module.columns && module.columns.length > 0) {
      if (module.id === 'task') {
        const nextColumns = [...module.columns];
        const progressIndex = nextColumns.indexOf('progress');
        const optionsIndex = nextColumns.indexOf('options_summary');
        if (progressIndex >= 0 && optionsIndex >= 0 && progressIndex > optionsIndex) {
          nextColumns.splice(progressIndex, 1);
          nextColumns.splice(optionsIndex, 0, 'progress');
        }
        // 简洁模式下隐藏 Task_Id 与配置项列，聚焦任务核心信息。
        if (taskCompactMode) {
          return nextColumns.filter((column) => column !== '_id' && column !== 'options_summary');
        }
        return nextColumns;
      }
      return module.columns;
    }
    const first = rows[0];
    if (!first || typeof first !== 'object') return [];
    const keys = Object.keys(first);
    const ordered: string[] = [];
    if (keys.includes(module.rowIdKey || '_id')) {
      ordered.push(module.rowIdKey || '_id');
    }
    keys.forEach((key) => {
      if (!ordered.includes(key)) ordered.push(key);
    });
    return ordered.slice(0, 10);
  }, [module.columns, module.id, module.rowIdKey, rows, taskCompactMode]);

  const rowIdKey = module.rowIdKey || '_id';
  const getRowId = useCallback((row: any): string => {
    const primary = normalizeRowIdValue(row?.[rowIdKey]);
    if (primary) return primary;
    if (module.id === 'task') {
      const taskFallback = normalizeRowIdValue(row?.task_id) || normalizeRowIdValue(row?.id);
      if (taskFallback) return taskFallback;
    }
    return '';
  }, [module.id, rowIdKey]);
  const showIndexColumn = Boolean(module.showIndex);
  const getColumnLabel = (column: string) => module.columnLabels?.[column] || humanizeField(column);
  const isColumnSortable = useCallback((column: string) => {
    if (!Array.isArray(module.sortableColumns)) return false;
    return module.sortableColumns.includes(column);
  }, [module.sortableColumns]);
  const getColumnSortDirection = useCallback((column: string): 'asc' | 'desc' | null => {
    const current = String(order || '').trim();
    if (!current) return null;
    if (current === `-${column}`) return 'desc';
    if (current === column || current === `+${column}`) return 'asc';
    return null;
  }, [order]);
  const toggleColumnSort = useCallback((column: string) => {
    if (!isColumnSortable(column)) return;
    setOrder((prev) => {
      const current = String(prev || '').trim();
      if (current === `-${column}`) return column;
      return `-${column}`;
    });
    setPage(1);
  }, [isColumnSortable]);
  const shouldWrapCell = useCallback((moduleId: string, column: string) => {
    if (moduleId === 'task' && ['target', 'options_summary'].includes(column)) return true;
    if (moduleId === 'task_schedule' && column === 'target') return true;
    if (moduleId === 'asset_site' && ['headers', 'finger'].includes(column)) return true;
    if (moduleId === 'site' && ['headers', 'finger'].includes(column)) return true;
    if ((moduleId === 'domain' || moduleId === 'asset_domain') && column === 'ips') return true;
    if ((moduleId === 'ip' || moduleId === 'asset_ip') && ['port_info.port_id', 'domain'].includes(column)) return true;
    if (moduleId === 'asset_scope' && column === 'scope') return true;
    if (moduleId === 'cert' && column === 'cert_summary') return true;
    if (moduleId === 'service' && ['ip_port', 'service_info.product'].includes(column)) return true;
    if (moduleId === 'vuln' && column === 'credential') return true;
    if (moduleId === 'nuclei_result' && ['vuln_url', 'curl_command'].includes(column)) return true;
    if (moduleId === 'wih' && ['content', 'source', 'site'].includes(column)) return true;
    if (moduleId === 'github_result' && ['path', 'human_content'].includes(column)) return true;
    if (moduleId === 'github_monitor_result' && ['path', 'human_content'].includes(column)) return true;
    return false;
  }, []);

  const moduleActions = module.actions || [];
  const visibleActions = useMemo(() => {
    if (module.id === 'asset_site' || module.id === 'site') {
      return moduleActions.filter((action) => !['asset_site_save_result_set', 'site_save_result_set'].includes(action.id));
    }
    if (module.id === 'asset_scope') {
      const assetScopeVisibleActionIds = ['asset_scope_add', 'asset_scope_delete'];
      return assetScopeVisibleActionIds
        .map((id) => moduleActions.find((action) => action.id === id))
        .filter((action): action is ModuleAction => Boolean(action));
    }
    if (module.id === 'policy') {
      return moduleActions.filter((action) => action.id === 'policy_add');
    }
    if (module.id === 'task_schedule') {
      return moduleActions.filter((action) => ['task_schedule_add', 'task_schedule_stop', 'task_schedule_delete'].includes(action.id));
    }
    if (module.id === 'task') {
      const taskVisibleActionIds = [
        'create_task',
        'fofa_submit',
        'task_stop_batch',
        'task_delete_batch',
        'task_batch_export_cip',
        'task_batch_export_domain',
        'task_batch_export_fileleak',
        'task_batch_export_ip',
        'task_batch_export_port',
        'task_batch_export_site',
        'task_batch_export_url',
        'task_batch_excel_report',
      ];
      return taskVisibleActionIds
        .map((id) => moduleActions.find((action) => action.id === id))
        .filter((action): action is ModuleAction => Boolean(action));
    }
    if (module.id === 'github_task') {
      return moduleActions.filter((action) => action.id === 'github_task_add');
    }
    if (module.id === 'github_scheduler') {
      return moduleActions.filter((action) => action.id === 'github_scheduler_add');
    }
    return moduleActions;
  }, [module.id, moduleActions]);

  const policyEditAction = module.id === 'policy'
    ? moduleActions.find((action) => action.id === 'policy_edit') || null
    : null;
  const assetScopeAddScopeAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_scope') || null
    : null;
  const assetScopeAddSchedulerAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_scheduler') || null
    : null;
  const assetScopeAddSiteMonitorAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_site_monitor') || null
    : null;
  const assetScopeAddWihMonitorAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_wih_monitor') || null
    : null;
  const githubSchedulerUpdateAction = module.id === 'github_scheduler'
    ? moduleActions.find((action) => action.id === 'github_scheduler_update') || null
    : null;
  const taskSyncAction = module.id === 'task'
    ? moduleActions.find((action) => action.id === 'task_sync') || null
    : null;

  const selectAllChecked = rows.length > 0 && selectedIds.length === rows.length;

  const openActionDialog = (action: ModuleAction, payloadOverrides?: JsonValue) => {
    const basePayload = deepClone(action.payloadTemplate || {});

    if (action.selectedField) {
      if (action.selectionMode === 'single') {
        basePayload[action.selectedField] = selectedIds[0] || '';
      } else if (action.selectionMode === 'multiple') {
        basePayload[action.selectedField] = selectedIds;
      }
    }

    const mergedPayload = payloadOverrides ? { ...basePayload, ...payloadOverrides } : basePayload;
    setDialogPayload(mergedPayload);
    setDialogAction(action);
  };

  const runAction = async (action: ModuleAction, payload: JsonValue, file?: File | null) => {
    setError('');
    setSuccess('');

    const selectionMode = action.selectionMode || 'none';
    let effectiveSelectedIds = [...selectedIds];
    const taskName = String(taskNameViewInput || '').trim();
    if (module.id === 'task' && selectionMode === 'multiple' && effectiveSelectedIds.length === 0 && taskName) {
      const taskIdsByName = await fetchTaskIdsByName(taskName);
      if (taskIdsByName.length === 0) {
        throw new Error(`未找到任务名为“${taskName}”的任务`);
      }
      effectiveSelectedIds = taskIdsByName;
    }

    if (selectionMode === 'single' && effectiveSelectedIds.length !== 1) {
      throw new Error('该操作需要且仅需要选择一条记录');
    }
    if (selectionMode === 'multiple' && effectiveSelectedIds.length === 0) {
      if (module.id === 'task') {
        throw new Error('请先选择记录，或输入任务名后再执行批量操作');
      }
      throw new Error('请先选择至少一条记录');
    }

    if (action.selectedField) {
      if (selectionMode === 'single') {
        payload[action.selectedField] = effectiveSelectedIds[0];
      }
      if (selectionMode === 'multiple') {
        payload[action.selectedField] = effectiveSelectedIds;
      }
    }

    if (isDeleteAction(action)) {
      const selectedCount = selectionMode === 'none' ? 0 : effectiveSelectedIds.length;
      const countText = selectedCount > 0 ? `已选择 ${selectedCount} 条记录。` : '';
      const confirmed = await askDeleteConfirm(
        `将执行「${action.label}」。${countText}此操作不可恢复。`
      );
      if (!confirmed) return;
    }

    const resolvedPath = applyPathTemplate(action.path, payload);
    if (/\\{\\w+\\}/.test(resolvedPath)) {
      throw new Error('存在未填写的路径参数，请补全后再执行');
    }

    let body: JsonValue | FormData | undefined;
    let query: JsonValue | undefined;

    if (action.method === 'GET') {
      if (action.sendPayloadAsQuery) {
        query = payload;
      }
    } else {
      if (action.fileFieldName) {
        if (!file) throw new Error('请先选择文件');
        const formData = new FormData();
        formData.append(action.fileFieldName, file);
        Object.entries(payload).forEach(([key, value]) => {
          if (value === undefined || value === null) return;
          formData.append(key, typeof value === 'string' ? value : JSON.stringify(value));
        });
        body = formData;
      } else {
        body = payload;
      }
    }

    const result = await requestApi(token, resolvedPath, {
      method: action.method,
      body,
      query,
      download: Boolean(action.download),
    });

    if (action.download) {
      setSuccess(`已触发下载: ${result?.data?.fileName || '导出文件'}`);
    } else {
      setSuccess(result?.message ? `执行成功: ${result.message}` : '执行成功');
    }

    if (action.reloadAfter !== false && module.listPath) {
      await loadRows();
    }
  };

  const runExport = async () => {
    if (!module.exportPath) return;

    let payload: JsonValue = {};
    if (module.exportPath.includes('{task_id}')) {
      if (selectedIds.length !== 1) {
        setError('下载单任务报告需要选择 1 条任务记录');
        return;
      }
      payload = { task_id: selectedIds[0] };
    }

    const resolved = applyPathTemplate(module.exportPath, payload);
    try {
      setError('');
      const filters = buildFilters();
      await requestApi(token, resolved, {
        method: 'GET',
        query: module.exportPath.includes('{task_id}') ? undefined : filters,
        download: true,
      });
      setSuccess('导出完成，文件已开始下载');
    } catch (err: any) {
      setError(err?.message || '导出失败');
    }
  };

  const runAssetIpExtraExport = async (kind: 'ip' | 'domain') => {
    if (module.id !== 'asset_ip' && module.id !== 'ip') return;
    const path = module.id === 'asset_ip'
      ? (kind === 'ip' ? '/asset_ip/export_ip/' : '/asset_ip/export_domain/')
      : (kind === 'ip' ? '/ip/export_ip/' : '/ip/export_domain/');
    const label = kind === 'ip' ? 'IP列表' : '关联域名';
    try {
      setError('');
      await requestApi(token, path, {
        method: 'GET',
        query: buildFilters(),
        download: true,
      });
      setSuccess(`导出${label}完成，文件已开始下载`);
    } catch (err: any) {
      setError(err?.message || `导出${label}失败`);
    }
  };

  const copyTextToClipboard = useCallback(async (rawText: string, label = '内容') => {
    const text = String(rawText || '').trim();
    if (!text) {
      setError(`没有可复制的${label}`);
      return;
    }
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', 'readonly');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setSuccess(`${label}已复制`);
    } catch (err: any) {
      setError(err?.message || `${label}复制失败`);
    }
  }, []);

  const closeRiskDialog = useCallback(() => {
    if (riskDialogSubmitting) return;
    setRiskDialogOpen(false);
    setRiskDialogError('');
  }, [riskDialogSubmitting]);

  useEffect(() => {
    if (!riskDialogOpen) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      closeRiskDialog();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [closeRiskDialog, riskDialogOpen]);

  const openAssetSiteRiskDialog = async () => {
    if (module.id !== 'asset_site') return;
    setRiskDialogLoading(true);
    setRiskDialogError('');
    setError('');
    setSuccess('');
    try {
      const filters = buildFilters();
      const saveResult = await requestApi(token, '/asset_site/save_result_set/', {
        method: 'GET',
        query: filters,
      });
      const resultData = saveResult?.data || {};
      const resultSetId = String(resultData.result_set_id || '').trim();
      const resultTotal = Number(resultData.result_total || 0);
      if (!resultSetId) {
        throw new Error('生成结果集失败，请调整筛选条件后重试');
      }

      const policyResponse = await requestApi(token, '/policy/', {
        method: 'GET',
        query: { page: 1, size: 1000, order: '-_id' },
      });
      const policyItems = normalizeListData(policyResponse).items;
      const options = policyItems
        .map((item) => {
          const policyId = String(item?._id || item?.policy_id || '').trim();
          const policyName = String(item?.name || '').trim() || '未命名策略';
          const pocConfig = Array.isArray(item?.policy?.poc_config) ? item.policy.poc_config : [];
          if (!policyId || pocConfig.length === 0) return null;
          return {
            policyId,
            policyName,
            pocCount: pocConfig.length,
          };
        })
        .filter((item): item is { policyId: string; policyName: string; pocCount: number } => Boolean(item));

      if (options.length === 0) {
        throw new Error('未找到可用策略，请先在策略配置中启用 PoC 插件');
      }

      const first = options[0];
      setRiskPolicies(options);
      setRiskPolicyId(first.policyId);
      setRiskTaskName(`风险巡航任务-${first.policyName}`);
      setRiskResultSetId(resultSetId);
      setRiskResultTotal(resultTotal);
      setRiskDialogOpen(true);
    } catch (err: any) {
      setError(err?.message || '风险任务下发准备失败');
    } finally {
      setRiskDialogLoading(false);
    }
  };

  const submitAssetSiteRiskTask = async () => {
    if (module.id !== 'asset_site') return;
    const taskName = riskTaskName.trim();
    if (!riskPolicyId) {
      setRiskDialogError('请选择策略');
      return;
    }
    if (!taskName) {
      setRiskDialogError('请填写任务名称');
      return;
    }
    if (!riskResultSetId) {
      setRiskDialogError('结果集 ID 无效，请重新生成');
      return;
    }

    setRiskDialogSubmitting(true);
    setRiskDialogError('');
    setError('');
    setSuccess('');
    try {
      await requestApi(token, '/task/policy/', {
        method: 'POST',
        body: {
          name: taskName,
          task_tag: 'risk_cruising',
          target: '',
          policy_id: riskPolicyId,
          result_set_id: riskResultSetId,
        },
      });
      setRiskDialogOpen(false);
      setSuccess(`风险任务下发成功，目标站点 ${riskResultTotal} 条`);
    } catch (err: any) {
      setRiskDialogError(err?.message || '风险任务下发失败');
    } finally {
      setRiskDialogSubmitting(false);
    }
  };

  // 资产分组的行内动作复用统一 ActionDialog，避免出现无后端能力的空壳按钮。
  const openAssetScopeRowActionDialog = (
    action: ModuleAction | null,
    scopeId: string,
    row: any,
    overrides?: JsonValue,
  ) => {
    if (module.id !== 'asset_scope') return;
    if (!action || !scopeId) return;
    const defaultName = String(row?.name || '').trim();
    const defaultScope = String(row?.scope || row?.scope_array || '').trim();
    openActionDialog(action, {
      scope_id: scopeId,
      name: defaultName || undefined,
      scope: defaultScope || undefined,
      ...overrides,
    });
  };

  const openPolicyTaskDialog = (row: any) => {
    if (module.id !== 'policy') return;
    const policyId = String(row?._id || row?.policy_id || '').trim();
    const policyName = String(row?.name || '').trim();
    if (!policyId) return;
    setPolicyTaskPolicyId(policyId);
    setPolicyTaskPolicyName(policyName || '策略');
    setPolicyTaskTag('task');
    setPolicyTaskName(`资产侦查任务-${policyName || '策略'}`);
    setPolicyTaskTarget('');
    setPolicyTaskError('');
    setPolicyTaskDialogOpen(true);
  };

  const closePolicyTaskDialog = useCallback(() => {
    if (policyTaskSubmitting) return;
    setPolicyTaskDialogOpen(false);
    setPolicyTaskError('');
  }, [policyTaskSubmitting]);

  useEffect(() => {
    if (!policyTaskDialogOpen) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      closePolicyTaskDialog();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [closePolicyTaskDialog, policyTaskDialogOpen]);

  const submitPolicyTask = async () => {
    if (module.id !== 'policy') return;
    const name = policyTaskName.trim();
    const normalizedTargets = policyTaskTarget
      .replace(/,/g, '\n')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter((item) => item);

    if (!policyTaskPolicyId) {
      setPolicyTaskError('策略ID无效，请重新打开任务下发');
      return;
    }
    if (!name) {
      setPolicyTaskError('请填写任务名称');
      return;
    }
    if (normalizedTargets.length === 0) {
      setPolicyTaskError('请填写目标，支持一行一个');
      return;
    }

    setPolicyTaskSubmitting(true);
    setPolicyTaskError('');
    setError('');
    setSuccess('');
    try {
      await requestApi(token, '/task/policy/', {
        method: 'POST',
        body: {
          name,
          task_tag: policyTaskTag,
          target: normalizedTargets.join('\n'),
          policy_id: policyTaskPolicyId,
        },
      });
      setPolicyTaskDialogOpen(false);
      setSuccess('任务下发成功');
    } catch (err: any) {
      setPolicyTaskError(err?.message || '任务下发失败');
    } finally {
      setPolicyTaskSubmitting(false);
    }
  };

  const deletePolicyRow = async (policyId: string) => {
    if (module.id !== 'policy') return;
    if (!policyId) return;
    if (!(await askDeleteConfirm('将删除该策略。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/policy/delete/', {
        method: 'POST',
        body: {
          policy_id: [policyId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const stopTaskScheduleRow = async (jobId: string) => {
    if (module.id !== 'task_schedule') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task_schedule/stop/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const recoverTaskScheduleRow = async (jobId: string) => {
    if (module.id !== 'task_schedule') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task_schedule/recover/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteTaskScheduleRow = async (jobId: string) => {
    if (module.id !== 'task_schedule') return;
    if (!jobId) return;
    if (!(await askDeleteConfirm('将删除该计划任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task_schedule/delete/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const stopGithubSchedulerRow = async (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_scheduler/stop/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const recoverGithubSchedulerRow = async (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_scheduler/recover/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteGithubSchedulerRow = async (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    if (!(await askDeleteConfirm('将删除该 GitHub 监控任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_scheduler/delete/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const stopGithubTaskRow = async (taskId: string) => {
    if (module.id !== 'github_task') return;
    if (!taskId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_task/stop/', {
        method: 'POST',
        body: {
          _id: [taskId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteGithubTaskRow = async (taskId: string) => {
    if (module.id !== 'github_task') return;
    if (!taskId) return;
    if (!(await askDeleteConfirm('将删除该 GitHub 任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_task/delete/', {
        method: 'POST',
        body: {
          _id: [taskId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const openTaskGlobalView = () => onOpenModule('site');

  const openTaskLocalView = (taskId: string) => {
    if (!taskId) return;
    onOpenModule('site', { task_id: taskId });
  };

  const fetchTaskIdsByName = useCallback(async (taskNameRaw: string) => {
    const taskName = String(taskNameRaw || '').trim();
    if (!taskName) return [];

    const response = await requestApi(token, '/task/', {
      method: 'GET',
      query: {
        page: 1,
        size: 10000,
        name: taskName,
        order: '-_id',
      },
    });

    const taskItems = normalizeListData(response).items || [];
    return Array.from(
      new Set(
        taskItems
          .map((item: any) => {
            return (
              normalizeRowIdValue(item?._id) ||
              normalizeRowIdValue(item?.task_id) ||
              normalizeRowIdValue(item?.id)
            );
          })
          .filter((id: string) => Boolean(id))
      )
    );
  }, [token]);

  const openTaskViewByName = async () => {
    if (module.id !== 'task') return;

    const taskName = String(taskNameViewInput || '').trim();
    if (!taskName) {
      setError('请先输入任务名后再进行同名任务查看');
      return;
    }

    setError('');
    setSuccess('');

    try {
      const taskIds = await fetchTaskIdsByName(taskName);

      if (taskIds.length === 0) {
        setError(`未找到任务名为“${taskName}”的任务`);
        return;
      }

      // 使用逗号拼接 task_id，后端会转换为 $in 查询，展示该任务名下全部任务扫描结果。
      onOpenModule('site', { task_id: taskIds.join(',') });
      setSuccess(`已切换查看任务名“${taskName}”的 ${taskIds.length} 条扫描结果`);
    } catch (err: any) {
      setError(err?.message || '同名任务查看失败');
    }
  };

  const openGithubSchedulerDetail = (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    onOpenModule('github_monitor_result', { github_scheduler_id: jobId });
  };

  const openGithubTaskDetail = (taskId: string) => {
    if (module.id !== 'github_task') return;
    if (!taskId) return;
    onOpenModule('github_result', { github_task_id: taskId });
  };

  const stopTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task/batch_stop/', {
        method: 'POST',
        body: {
          task_id: [taskId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (!(await askDeleteConfirm('将删除该任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task/delete/', {
        method: 'POST',
        body: {
          task_id: [taskId],
          del_task_data: false,
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const restartTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task/restart/', {
        method: 'POST',
        body: {
          task_id: [taskId],
        },
      });
      setSuccess(result?.message ? `重启成功: ${result.message}` : '重启成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '重启失败');
    }
  };

  const exportTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    setError('');
    setSuccess('');
    try {
      await requestApi(token, `/export/${taskId}`, {
        method: 'GET',
        download: true,
      });
      setSuccess('导出成功');
    } catch (err: any) {
      setError(err?.message || '导出失败');
    }
  };

  const syncTaskRow = (taskId: string, row: any) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (!taskSyncAction) {
      setError('未找到任务同步动作配置');
      return;
    }
    openActionDialog(taskSyncAction, {
      task_id: taskId,
      scope_id: String(row?.scope_id || '').trim(),
    });
  };

  const selectionStatus =
    selectedIds.length > 0 ? `${selectedIds.length} 条已选择` : hasList ? '未选择记录' : '动作模式';
  const showTaskRowOperate = module.id === 'task';
  const showAssetScopeRowOperate = module.id === 'asset_scope';
  const showPolicyRowOperate = module.id === 'policy';
  const showTaskScheduleRowOperate = module.id === 'task_schedule';
  const showGithubTaskRowOperate = module.id === 'github_task';
  const showGithubSchedulerRowOperate = module.id === 'github_scheduler';
  const hasRowOperate =
    showTaskRowOperate ||
    showAssetScopeRowOperate ||
    showPolicyRowOperate ||
    showTaskScheduleRowOperate ||
    showGithubTaskRowOperate ||
    showGithubSchedulerRowOperate;
  const rowOperateGroupClass = 'inline-flex flex-nowrap items-center justify-center gap-2 min-w-max';
  const rowOperateButtonClass = 'px-3 py-1.5 rounded-lg border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition shrink-0';
  const rowOperateButtonDisabledClass = `${rowOperateButtonClass} disabled:opacity-40 disabled:cursor-not-allowed`;
  const rowOperateColumnWidthClass = showAssetScopeRowOperate
    ? 'min-w-[760px]'
    : showTaskRowOperate
      ? 'min-w-[520px]'
      : showPolicyRowOperate
        ? 'min-w-[300px]'
        : showTaskScheduleRowOperate
          ? 'min-w-[220px]'
          : showGithubTaskRowOperate
            ? 'min-w-[220px]'
            : showGithubSchedulerRowOperate
              ? 'min-w-[300px]'
              : '';

  return (
    <div className="p-8 space-y-6">
      <div className="flex flex-col xl:flex-row xl:items-end xl:justify-between gap-4">
        <div>
          <h2 className="text-4xl font-black tracking-tight">{module.label}</h2>
          <p className="text-brand-text-muted mt-2 text-sm">{module.description}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <StatusPill text={selectionStatus} type="info" />
          {success ? <StatusPill text={success} type="success" /> : null}
          {error ? <StatusPill text={error} type="error" /> : null}
        </div>
      </div>

      {['scheduler', 'asset_scope', 'asset_site', 'asset_domain', 'asset_ip', 'asset_wih'].includes(module.id) ? (
        <div className="flex items-center gap-2">
          {[
            { id: 'scheduler', label: '资产监控' },
            { id: 'asset_scope', label: '资产分组' },
            { id: 'asset_site', label: '组站点' },
            { id: 'asset_domain', label: '组子域名' },
            { id: 'asset_ip', label: '组IP' },
            { id: 'asset_wih', label: '组WIH' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => onOpenModule(item.id)}
              className={`px-4 py-2 rounded-xl border text-sm font-semibold transition ${
                module.id === item.id
                  ? 'border-brand-accent bg-brand-accent/10 text-brand-accent'
                  : 'border-brand-border text-brand-text-muted hover:text-white hover:bg-brand-bg/70'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
      {['site', 'domain', 'ip', 'cert', 'service', 'fileleak', 'url', 'vuln', 'cip', 'nuclei_result', 'stat_finger', 'wih'].includes(module.id) ? (
        <div className="flex items-center gap-2">
          {hasExternalFilters ? (
            <button
              onClick={() => onOpenModule('task')}
              className="px-4 py-2.5 rounded-xl border text-sm font-bold transition inline-flex items-center gap-1.5 bg-brand-accent text-white border-brand-accent shadow-sm hover:bg-brand-accent/90 hover:shadow-md"
              title="返回任务管理"
            >
              <ChevronLeft className="w-4 h-4" />
              返回任务管理
            </button>
          ) : null}
          {TASK_DETAIL_TABS.map((item) => (
            <button
              key={item.id}
              onClick={() => onOpenModule(item.id, hasExternalFilters ? activeExternalFilters : undefined)}
              className={`px-4 py-2 rounded-xl border text-sm font-semibold transition ${
                module.id === item.id
                  ? 'border-brand-accent bg-brand-accent/10 text-brand-accent'
                  : 'border-brand-border text-brand-text-muted hover:text-white hover:bg-brand-bg/70'
              }`}
            >
              {`${item.label} - ${
                typeof taskDetailCounts[item.id] === 'number'
                  ? taskDetailCounts[item.id]
                  : taskDetailCountLoading
                    ? '...'
                    : 0
              }`}
            </button>
          ))}
        </div>
      ) : null}

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
        {hasExternalFilters ? (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-brand-text-muted">查看筛选条件:</span>
            {Object.entries(activeExternalFilters).map(([key, value]) => (
              <span
                key={key}
                title={`${key}=${String(value ?? '')}`}
                className="text-xs px-2.5 py-1 rounded-lg border border-brand-border bg-brand-bg/60 font-mono max-w-[42rem] whitespace-pre-wrap break-all leading-relaxed"
              >
                {formatExternalFilterChipText(key, value)}
              </span>
            ))}
            {onClearExternalFilters ? (
              <button
                onClick={onClearExternalFilters}
                className="px-3 py-1.5 rounded-lg border border-brand-border text-xs font-semibold hover:bg-brand-bg/70 transition"
              >
                清除筛选
              </button>
            ) : null}
          </div>
        ) : null}
        {hasAdvancedSearch ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {(module.searchFields || []).map((field) => (
                <div key={field.key} className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">{field.label}：</label>
                  {field.inputType === 'select' ? (
                    <div className="relative">
                      <select
                        value={String(searchForm?.[field.key] ?? '')}
                        className={UNIFIED_SELECT_CLASS}
                        onChange={(event) => {
                          const value = event.target.value;
                          setSearchForm((prev) => ({ ...prev, [field.key]: value }));
                        }}
                      >
                        {getSearchFieldOptions(field).map((option) => (
                          <option key={`${field.key}-${option.value}`} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                      <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                  ) : (
                    <input
                      type={field.inputType === 'number' ? 'number' : 'text'}
                      value={String(searchForm?.[field.key] ?? '')}
                      placeholder={field.placeholder}
                      className="w-full bg-brand-bg border border-brand-border rounded-xl py-2.5 px-3 text-sm focus:outline-none focus:border-brand-accent"
                      onChange={(event) => {
                        const value = event.target.value;
                        setSearchForm((prev) => ({ ...prev, [field.key]: value }));
                      }}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          event.preventDefault();
                          setPage(1);
                          void loadRows();
                        }
                      }}
                    />
                  )}
                </div>
              ))}
            </div>

            <div className="flex flex-wrap gap-2">
              {module.id !== 'task' ? (
                <button
                  onClick={() => {
                    setPage(1);
                    void loadRows();
                  }}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                  disabled={loading || !hasList}
                >
                  <Search className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                  搜索
                </button>
              ) : null}
              {module.id !== 'task' ? (
                <button
                  onClick={clearSearchFilters}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                  disabled={loading || !hasList}
                >
                  <RefreshCw className="w-4 h-4" />
                  {module.id === 'asset_site' ? '清除' : '重置'}
                </button>
              ) : null}
              {module.exportPath && module.id !== 'task' && module.id !== 'asset_scope' ? (
                <button
                  onClick={() => void runExport()}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  {module.id === 'asset_site' || module.id === 'site'
                    ? '导出站点'
                    : module.id === 'domain'
                      ? '导出子域名'
                      : module.id === 'asset_ip' || module.id === 'ip'
                        ? '导出IP端口'
                        : '导出'}
                </button>
              ) : null}
              {module.id === 'asset_site' ? (
                <button
                  onClick={() => void openAssetSiteRiskDialog()}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                  disabled={riskDialogLoading}
                >
                  <Play className={`w-4 h-4 ${riskDialogLoading ? 'animate-spin' : ''}`} />
                  风险任务下发
                </button>
              ) : null}
              {module.id === 'task' ? (
                <button
                  onClick={openTaskGlobalView}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                >
                  <Eye className="w-4 h-4" />
                  全局查看
                </button>
              ) : null}
              {module.id === 'task' ? (
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={taskNameViewInput}
                    onChange={(event) => setTaskNameViewInput(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') {
                        event.preventDefault();
                        void openTaskViewByName();
                      }
                    }}
                    placeholder="输入任务名（查看该任务名下全部扫描）"
                    className="w-72 bg-brand-bg border border-brand-border rounded-xl py-2.5 px-3 text-sm focus:outline-none focus:border-brand-accent"
                  />
                  <button
                    onClick={() => void openTaskViewByName()}
                    disabled={!String(taskNameViewInput || '').trim()}
                    className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Eye className="w-4 h-4" />
                    同名任务查看
                  </button>
                </div>
              ) : null}
              {module.id === 'task' ? (
                <button
                  type="button"
                  onClick={() => setTaskCompactMode((prev) => !prev)}
                  className={`px-4 py-2.5 rounded-xl border text-sm font-semibold transition ${
                    taskCompactMode
                      ? 'border-brand-accent bg-brand-accent/10 text-brand-accent'
                      : 'border-brand-border text-brand-text-muted hover:text-white hover:bg-brand-bg/70'
                  }`}
                  title={taskCompactMode ? '当前为简洁模式，点击切换完整模式' : '当前为完整模式，点击切换简洁模式'}
                >
                  {taskCompactMode ? '简洁模式' : '完整模式'}
                </button>
              ) : null}
              {module.id === 'asset_ip' || module.id === 'ip' ? (
                <button
                  onClick={() => void runAssetIpExtraExport('ip')}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  导出IP列表
                </button>
              ) : null}
              {module.id === 'asset_ip' || module.id === 'ip' ? (
                <button
                  onClick={() => void runAssetIpExtraExport('domain')}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  导出关联域名
                </button>
              ) : null}
            </div>
          </div>
        ) : (
          <div className="flex flex-col lg:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-brand-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                value={quickFilter}
                onChange={(event) => {
                  setQuickFilter(event.target.value);
                  setPage(1);
                }}
                placeholder={module.quickFilterKey ? `快速筛选字段: ${module.quickFilterKey}` : '快速筛选'}
                className="w-full bg-brand-bg border border-brand-border rounded-xl py-2.5 pl-9 pr-3 text-sm"
              />
            </div>

            <button
              onClick={() => void loadRows()}
              className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
              disabled={loading || !hasList}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>

            {module.exportPath ? (
              <button
                onClick={() => void runExport()}
                className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                导出
              </button>
            ) : null}
          </div>
        )}

        {visibleActions.length > 0 ? (
          <div className="flex flex-wrap gap-2 pt-1">
            {visibleActions.map((action) => {
              const needSingle = action.selectionMode === 'single';
              const needMultiple = action.selectionMode === 'multiple';
              const canUseTaskNameForBatch =
                module.id === 'task' && needMultiple && selectedIds.length === 0 && Boolean(String(taskNameViewInput || '').trim());
              const disabled =
                (needSingle && selectedIds.length !== 1) ||
                (needMultiple && selectedIds.length === 0 && !canUseTaskNameForBatch);

              return (
                <button
                  key={action.id}
                  onClick={() => openActionDialog(action)}
                  disabled={disabled}
                  className="px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide uppercase border border-brand-border hover:bg-brand-bg/70 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  {action.label}
                </button>
              );
            })}
            {module.id === 'asset_scope' && module.exportPath ? (
              <button
                onClick={() => void runExport()}
                className="px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide uppercase border border-brand-border hover:bg-brand-bg/70 transition flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                批量导出
              </button>
            ) : null}
          </div>
        ) : null}
      </div>

      {hasList ? (
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl overflow-hidden">
          <div className="overflow-auto">
            <table className="w-full border-collapse text-sm md:text-[15px]">
              <thead className="bg-brand-bg/40 border-b border-brand-border">
                <tr>
                  <th className="px-4 py-3 w-12 text-center">
                    <input
                      type="checkbox"
                      checked={selectAllChecked}
                      className="h-5 w-5 cursor-pointer rounded-md border border-brand-border bg-brand-bg"
                      onChange={(event) => {
                        if (event.target.checked) {
                          const ids = rows
                            .map((row) => getRowId(row))
                            .filter((value) => value);
                          setSelectedIds(ids);
                        } else {
                          setSelectedIds([]);
                        }
                      }}
                    />
                  </th>
                  {showIndexColumn ? (
                    <th className="px-4 py-3 text-sm font-black text-brand-text-muted whitespace-nowrap text-center">序号</th>
                  ) : null}
                  {columns.map((column) => {
                    const sortable = isColumnSortable(column);
                    const direction = getColumnSortDirection(column);
                    return (
                      <th key={column} className="px-4 py-3 text-sm font-black text-brand-text-muted whitespace-nowrap text-center">
                        {sortable ? (
                          <button
                            type="button"
                            onClick={() => toggleColumnSort(column)}
                            className="inline-flex items-center justify-center gap-1.5 hover:text-brand-accent transition"
                            title={direction === 'desc' ? '当前降序，点击切换升序' : '点击按此列降序'}
                          >
                            <span>{getColumnLabel(column)}</span>
                            <span className={`inline-flex ${direction ? 'text-brand-accent' : 'text-brand-text-muted/70'}`}>
                              {direction === 'desc' ? (
                                <ChevronDown className="w-3.5 h-3.5" />
                              ) : direction === 'asc' ? (
                                <ChevronUp className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronsUpDown className="w-3.5 h-3.5" />
                              )}
                            </span>
                          </button>
                        ) : (
                          getColumnLabel(column)
                        )}
                      </th>
                    );
                  })}
                  {hasRowOperate ? (
                    <th className={`px-4 py-3 text-sm font-black text-brand-text-muted whitespace-nowrap text-center ${rowOperateColumnWidthClass}`}>操作</th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, rowIndex) => {
                  const id = getRowId(row);
                  const checked = selectedIds.includes(id);
                  const scopeExpandKey = id || `scope-row-${page}-${rowIndex}`;
                  const scheduleTargetExpandKey = id || `task-schedule-row-${page}-${rowIndex}`;
                  const taskOptionExpandKey = id || `task-option-row-${page}-${rowIndex}`;

                  return (
                    <tr key={id || Math.random()} className="border-b border-brand-border/60 hover:bg-white/5 transition">
                      <td className="px-4 py-3 text-center align-middle">
                        <input
                          type="checkbox"
                          checked={checked}
                          className="h-5 w-5 cursor-pointer rounded-md border border-brand-border bg-brand-bg"
                          onChange={(event) => {
                            if (!id) return;
                            if (event.target.checked) {
                              setSelectedIds((prev) => [...new Set([...prev, id])]);
                            } else {
                              setSelectedIds((prev) => prev.filter((item) => item !== id));
                            }
                          }}
                        />
                      </td>
                      {showIndexColumn ? (
                        <td className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                          {(page - 1) * size + rowIndex + 1}
                        </td>
                      ) : null}
                      {columns.map((column) => {
                        const wrapCell = shouldWrapCell(module.id, column);
                        const baseClassName = wrapCell
                          ? 'px-4 py-3 align-top text-sm whitespace-pre-wrap break-all text-center leading-relaxed min-w-[220px] max-w-[560px]'
                          : 'px-4 py-3 align-middle text-sm whitespace-nowrap text-center';

                        if (module.id === 'asset_scope' && column === 'scope') {
                          const scopeText = formatModuleCellValue(module.id, column, row);
                          const scopeLines = scopeText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 4;
                          const shouldCollapse = scopeLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedScopeRows[scopeExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${scopeLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (scopeLines.length > 0 ? scopeLines.join('\n') : '-');

                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[640px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed">{renderedText}</div>
                              <div className="mt-2 flex flex-wrap items-center justify-center gap-3">
                                {shouldCollapse ? (
                                  <button
                                    onClick={() =>
                                      setExpandedScopeRows((prev) => ({
                                        ...prev,
                                        [scopeExpandKey]: !isExpanded,
                                      }))
                                    }
                                    className="text-xs font-semibold text-brand-accent hover:underline"
                                  >
                                    {isExpanded ? '收起' : '显示全部'}
                                  </button>
                                ) : null}
                                <button
                                  type="button"
                                  onClick={() =>
                                    void copyTextToClipboard(scopeLines.length > 0 ? scopeLines.join('\n') : scopeText, '资产范围')
                                  }
                                  className="text-xs font-semibold text-brand-accent hover:underline"
                                >
                                  复制
                                </button>
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'task_schedule' && column === 'target') {
                          const targetText = formatModuleCellValue(module.id, column, row);
                          const targetLines = targetText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 4;
                          const shouldCollapse = targetLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedTaskScheduleTargetRows[scheduleTargetExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${targetLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (targetLines.length > 0 ? targetLines.join('\n') : '-');

                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[640px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed font-mono text-center">{renderedText}</div>
                              {shouldCollapse ? (
                                <button
                                  onClick={() =>
                                    setExpandedTaskScheduleTargetRows((prev) => ({
                                      ...prev,
                                      [scheduleTargetExpandKey]: !isExpanded,
                                    }))
                                  }
                                  className="mt-2 block mx-auto text-xs font-semibold text-brand-accent hover:underline"
                                >
                                  {isExpanded ? '收起' : '显示全部'}
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'options_summary') {
                          const optionText = formatModuleCellValue(module.id, column, row);
                          const optionLines = optionText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 3;
                          const shouldCollapse = optionLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedTaskOptionRows[taskOptionExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${optionLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (optionLines.length > 0 ? optionLines.join('\n') : '-');

                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[640px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed text-center">{renderedText}</div>
                              {shouldCollapse ? (
                                <button
                                  onClick={() =>
                                    setExpandedTaskOptionRows((prev) => ({
                                      ...prev,
                                      [taskOptionExpandKey]: !isExpanded,
                                    }))
                                  }
                                  className="mt-2 block mx-auto text-xs font-semibold text-brand-accent hover:underline"
                                >
                                  {isExpanded ? '收起' : '显示全部'}
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'wih' && column === 'record_type') {
                          const recordType = String(row?.record_type || '').trim();
                          const sensitive = isSensitiveWihRow(row);
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span className={getWihRecordTypeTagClass(recordType, sensitive)}>
                                {recordType || '-'}
                              </span>
                            </td>
                          );
                        }

                        if (module.id === 'wih' && column === 'content') {
                          const sensitive = isSensitiveWihRow(row);
                          const contentText = formatModuleCellValue(module.id, column, row);
                          // 敏感记录在 WIH 中添加显著色块与标识，便于人工优先复核。
                          const contentClass = sensitive
                            ? 'whitespace-pre-wrap break-all leading-relaxed rounded-xl border border-brand-danger/45 bg-brand-danger/10 px-3 py-2'
                            : 'whitespace-pre-wrap break-all leading-relaxed';
                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[680px]">
                              <div className={contentClass}>{contentText}</div>
                              {sensitive ? (
                                <div className="mt-2 text-[11px] font-black text-brand-danger">敏感信息</div>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'cip' && (column === 'ip_count' || column === 'domain_count')) {
                          const taskId = String(row?.task_id || '').trim();
                          const cidrPrefix = buildCidrPrefix(row?.cidr_ip);
                          const destinationModule = column === 'ip_count' ? 'ip' : 'domain';
                          const nextFilters: JsonValue = {};
                          if (taskId) nextFilters.task_id = taskId;
                          if (cidrPrefix) {
                            if (column === 'ip_count') {
                              nextFilters.ip = cidrPrefix;
                            } else {
                              nextFilters.ips = cidrPrefix;
                            }
                          }
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <button
                                type="button"
                                onClick={() => onOpenModule(destinationModule, nextFilters)}
                                className="text-brand-accent hover:underline font-semibold"
                                title={column === 'ip_count' ? '跳转到IP并自动按C段筛选' : '跳转到子域名并自动按C段筛选'}
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'progress') {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <div className="mx-auto w-[170px] space-y-1 text-left">
                                <div className="flex items-center justify-between gap-2 text-xs">
                                  <span className="font-semibold text-brand-text-muted">进度</span>
                                  <span className="font-black text-white">{formatModuleCellValue(module.id, column, row)}</span>
                                </div>
                                <div className="h-2 bg-brand-bg rounded-full border border-brand-border overflow-hidden">
                                  <div
                                    className="h-full bg-brand-accent rounded-full transition-all duration-300"
                                    style={{ width: `${getTaskProgressPercent(row)}%` }}
                                  />
                                </div>
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'target') {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[220px] max-w-[560px]">
                              <button
                                onClick={() => openTaskLocalView(id)}
                                className="text-brand-accent hover:underline font-mono whitespace-pre-wrap break-all text-center inline-block w-full leading-relaxed"
                                title="点击查看该任务详情"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'status') {
                          const rawStatus = String(row?.status || '').trim().toLowerCase();
                          const statusText = formatModuleCellValue(module.id, column, row);
                          if (rawStatus === 'error') {
                            return (
                              <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                                <button
                                  type="button"
                                  onClick={() => openTaskErrorDialog(row)}
                                  className="inline-flex items-center gap-1 text-brand-danger hover:underline font-semibold"
                                  title="点击查看异常详情"
                                >
                                  <AlertTriangle className="w-4 h-4" />
                                  <span>{statusText}</span>
                                </button>
                              </td>
                            );
                          }
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              {statusText}
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'name') {
                          return (
                            <td key={column} className={baseClassName}>
                              <button
                                onClick={() => openTaskLocalView(id)}
                                className="text-brand-accent hover:underline text-center inline-block w-full"
                                title="点击查看该任务详情"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'task' && (column === 'start_time' || column === 'end_time')) {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span className="inline-block min-w-[19ch] font-mono tabular-nums">
                                {formatModuleCellValue(module.id, column, row)}
                              </span>
                            </td>
                          );
                        }

                        if ((module.id === 'asset_site' || module.id === 'site') && column === 'finger') {
                          return (
                            <td
                              key={column}
                              className="px-4 py-3 align-middle text-sm text-center whitespace-pre-wrap break-all leading-relaxed min-w-[220px] max-w-[560px]"
                            >
                              {formatModuleCellValue(module.id, column, row)}
                            </td>
                          );
                        }

                        if (isLikelyIdColumn(column)) {
                          const rawIdValue = getValueByPath(row, column);
                          const fullIdText = normalizeValue(rawIdValue);
                          const compactIdText = fullIdText === '-' ? '-' : truncateMiddleText(fullIdText, 38, 14, 12);
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span
                                title={fullIdText}
                                className="inline-block max-w-[260px] truncate align-middle font-mono"
                              >
                                {compactIdText}
                              </span>
                            </td>
                          );
                        }

                        if (module.id === 'site' && column === 'screenshot') {
                          const screenshot = String(row?.screenshot || '').trim();
                          if (!screenshot) {
                            return (
                              <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                                -
                              </td>
                            );
                          }
                          let screenshotUrl = screenshot;
                          if (screenshot.startsWith('/image/')) {
                            screenshotUrl = `/api${screenshot}`;
                          } else if (!/^https?:\/\//i.test(screenshot)) {
                            const taskId = String(row?.task_id || '').trim();
                            if (taskId) {
                              screenshotUrl = `/api/image/${taskId}/${screenshot.replace(/^\/+/, '')}`;
                            }
                          }

                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[180px]">
                              <button
                                type="button"
                                onClick={() =>
                                  setScreenshotPreview({
                                    url: screenshotUrl,
                                    title: String(row?.site || row?.hostname || row?.title || '截图预览'),
                                  })
                                }
                                className="inline-flex items-center justify-center p-1 rounded-xl border border-transparent hover:border-brand-accent/60 transition"
                                title="点击预览截图"
                              >
                                <img
                                  src={screenshotUrl}
                                  alt="screenshot"
                                  className="w-32 h-20 rounded-lg border border-brand-border object-cover bg-brand-bg"
                                  loading="lazy"
                                />
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'github_scheduler' && column === 'name') {
                          return (
                            <td key={column} className={baseClassName}>
                              <button
                                onClick={() => openGithubSchedulerDetail(id)}
                                className="text-brand-accent hover:underline text-center inline-block w-full"
                                title="查看该监控任务结果"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'github_task' && column === 'name') {
                          return (
                            <td key={column} className={baseClassName}>
                              <button
                                onClick={() => openGithubTaskDetail(id)}
                                className="text-brand-accent hover:underline text-center inline-block w-full"
                                title="查看该任务结果"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if ((module.id === 'github_result' || module.id === 'github_monitor_result') && column === 'path') {
                          return (
                            <td
                              key={column}
                              className="px-4 py-3 align-middle text-sm text-center whitespace-pre-wrap break-all leading-relaxed min-w-[260px] max-w-[640px]"
                            >
                              {formatModuleCellValue(module.id, column, row)}
                            </td>
                          );
                        }

                        return (
                          <td key={column} className={baseClassName}>
                            {formatModuleCellValue(module.id, column, row)}
                          </td>
                        );
                      })}
                      {hasRowOperate ? (
                        <td className={`px-4 py-3 align-middle whitespace-nowrap text-center ${rowOperateColumnWidthClass}`}>
                          {showTaskRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              <button
                                onClick={() => syncTaskRow(id, row)}
                                className={rowOperateButtonClass}
                              >
                                同步
                              </button>
                              <button
                                onClick={() => void exportTaskRow(id)}
                                className={rowOperateButtonClass}
                              >
                                导出
                              </button>
                              <button
                                onClick={() => void stopTaskRow(id)}
                                disabled={['done', 'stop', 'error'].includes(String(row?.status || '').toLowerCase())}
                                className={rowOperateButtonDisabledClass}
                              >
                                停止
                              </button>
                              <button
                                onClick={() => void deleteTaskRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                              <button
                                onClick={() => void restartTaskRow(id)}
                                disabled={!['done', 'stop', 'error'].includes(String(row?.status || '').toLowerCase())}
                                className={rowOperateButtonDisabledClass}
                              >
                                重启
                              </button>
                            </div>
                          ) : null}
                          {showAssetScopeRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              {assetScopeAddScopeAction ? (
                                <button
                                  onClick={() => openAssetScopeRowActionDialog(assetScopeAddScopeAction, id, row, { scope: '' })}
                                  className={rowOperateButtonClass}
                                >
                                  添加资产分组范围
                                </button>
                              ) : null}
                              {assetScopeAddSchedulerAction ? (
                                <button
                                  onClick={() =>
                                    openAssetScopeRowActionDialog(assetScopeAddSchedulerAction, id, row, {
                                      domain: String(row?.scope || '').replace(/,/g, '\n'),
                                      name: `监控-${String(row?.name || '').trim() || id.slice(-6)}`,
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  添加监控任务
                                </button>
                              ) : null}
                              {assetScopeAddSiteMonitorAction ? (
                                <button
                                  onClick={() =>
                                    openAssetScopeRowActionDialog(assetScopeAddSiteMonitorAction, id, row, {
                                      name: `站点监控-${String(row?.name || '').trim() || id.slice(-6)}`,
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  添加站点监控任务
                                </button>
                              ) : null}
                              {assetScopeAddWihMonitorAction ? (
                                <button
                                  onClick={() =>
                                    openAssetScopeRowActionDialog(assetScopeAddWihMonitorAction, id, row, {
                                      name: `WIH监控-${String(row?.name || '').trim() || id.slice(-6)}`,
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  添加WIH监控任务
                                </button>
                              ) : null}
                            </div>
                          ) : null}
                          {showPolicyRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              <button
                                onClick={() => openPolicyTaskDialog(row)}
                                className={rowOperateButtonClass}
                              >
                                任务下发
                              </button>
                              {policyEditAction ? (
                                <button
                                  onClick={() =>
                                    openActionDialog(policyEditAction, {
                                      policy_id: id,
                                      policy_data: {
                                        name: row?.name || '',
                                        desc: row?.desc || '',
                                        policy: row?.policy || {},
                                      },
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  编辑
                                </button>
                              ) : null}
                              <button
                                onClick={() => void deletePolicyRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                          {showTaskScheduleRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              {String(row?.status || '').toLowerCase() === 'stop' ? (
                                <button
                                  onClick={() => void recoverTaskScheduleRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  恢复
                                </button>
                              ) : (
                                <button
                                  onClick={() => void stopTaskScheduleRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  停止
                                </button>
                              )}
                              <button
                                onClick={() => void deleteTaskScheduleRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                          {showGithubTaskRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              <button
                                onClick={() => void stopGithubTaskRow(id)}
                                disabled={['done', 'stop', 'error'].includes(String(row?.status || '').toLowerCase())}
                                className={rowOperateButtonDisabledClass}
                              >
                                停止
                              </button>
                              <button
                                onClick={() => void deleteGithubTaskRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                          {showGithubSchedulerRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              {githubSchedulerUpdateAction ? (
                                <button
                                  onClick={() =>
                                    openActionDialog(githubSchedulerUpdateAction, {
                                      _id: id,
                                      name: row?.name || '',
                                      keyword: row?.keyword || '',
                                      cron: row?.cron || '',
                                      dingding_notify: row?.dingding_notify !== false,
                                      kb_notify_enable: Boolean(row?.kb_notify_enable),
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  修改
                                </button>
                              ) : null}
                              {String(row?.status || '').toLowerCase() === 'stop' ? (
                                <button
                                  onClick={() => void recoverGithubSchedulerRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  恢复
                                </button>
                              ) : (
                                <button
                                  onClick={() => void stopGithubSchedulerRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  停止
                                </button>
                              )}
                              <button
                                onClick={() => void deleteGithubSchedulerRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                        </td>
                      ) : null}
                    </tr>
                  );
                })}
                {rows.length === 0 && !loading ? (
                  <tr>
                    <td
                      colSpan={Math.max(columns.length + 1 + (showIndexColumn ? 1 : 0) + (hasRowOperate ? 1 : 0), 2)}
                      className="px-4 py-10 text-center text-brand-text-muted"
                    >
                      暂无数据
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 border-t border-brand-border bg-brand-bg/30 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="text-xs text-brand-text-muted font-semibold">
              共 {total} 条，当前第 {page}/{totalPages} 页
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                disabled={page <= 1}
                className="px-3.5 py-2 rounded-xl border border-brand-border text-sm disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <div className="relative">
                <select
                  value={size}
                  onChange={(event) => {
                    setSize(Number(event.target.value));
                    setPage(1);
                  }}
                  className={`${UNIFIED_SELECT_CLASS} w-auto min-w-[108px] py-2`}
                >
                  {[10, 20, 50, 100].map((option) => (
                    <option key={option} value={option}>
                      {option} / 页
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
              </div>
              <button
                onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
                disabled={page >= totalPages}
                className="px-3.5 py-2 rounded-xl border border-brand-border text-sm disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-10 text-center text-brand-text-muted text-sm">
          该模块为操作中心，无列表数据。请使用上方动作按钮执行。
        </div>
      )}

      {dialogAction ? (
        <ActionDialog
          token={token}
          action={dialogAction}
          initialPayload={dialogPayload}
          onClose={() => setDialogAction(null)}
          onSubmit={async (payload, file) => {
            await runAction(dialogAction, payload, file);
          }}
        />
      ) : null}

      {riskDialogOpen ? (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between">
              <div>
                <h4 className="text-lg font-black">添加风险巡航任务</h4>
                <p className="text-xs text-brand-text-muted mt-1">
                  已匹配站点 {riskResultTotal} 条，结果集 ID: {riskResultSetId}
                </p>
              </div>
              <button
                onClick={closeRiskDialog}
                disabled={riskDialogSubmitting}
                className="p-2 rounded-lg hover:bg-brand-bg/70 transition disabled:opacity-40"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">策略</label>
                <div className="relative">
                  <select
                    value={riskPolicyId}
                    onChange={(event) => {
                      const nextPolicyId = event.target.value;
                      setRiskPolicyId(nextPolicyId);
                      const selectedPolicy = riskPolicies.find((item) => item.policyId === nextPolicyId);
                      if (!selectedPolicy) return;
                      if (!riskTaskName.trim() || riskTaskName.startsWith('风险巡航任务-')) {
                        setRiskTaskName(`风险巡航任务-${selectedPolicy.policyName}`);
                      }
                    }}
                    className={UNIFIED_SELECT_CLASS}
                    disabled={riskDialogSubmitting}
                  >
                    {riskPolicies.map((option) => (
                      <option key={option.policyId} value={option.policyId}>
                        {option.policyName} (PoC: {option.pocCount})
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">任务名称</label>
                <input
                  value={riskTaskName}
                  onChange={(event) => setRiskTaskName(event.target.value)}
                  disabled={riskDialogSubmitting}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="风险巡航任务-策略名"
                />
              </div>

              {riskDialogError ? (
                <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2">
                  {riskDialogError}
                </div>
              ) : null}

              <div className="flex justify-end gap-3">
                <button
                  onClick={closeRiskDialog}
                  disabled={riskDialogSubmitting}
                  className="px-5 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition disabled:opacity-40"
                >
                  取消
                </button>
                <button
                  onClick={() => void submitAssetSiteRiskTask()}
                  disabled={riskDialogSubmitting}
                  className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider"
                >
                  {riskDialogSubmitting ? '下发中...' : '确认下发'}
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {policyTaskDialogOpen ? (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between">
              <div>
                <h4 className="text-lg font-black">任务下发</h4>
                <p className="text-xs text-brand-text-muted mt-1">策略：{policyTaskPolicyName || '-'}</p>
              </div>
              <button
                onClick={closePolicyTaskDialog}
                disabled={policyTaskSubmitting}
                className="p-2 rounded-lg hover:bg-brand-bg/70 transition disabled:opacity-40"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">任务类型</label>
                <div className="relative">
                  <select
                    value={policyTaskTag}
                    onChange={(event) => {
                      const nextTag = event.target.value === 'risk_cruising' ? 'risk_cruising' : 'task';
                      setPolicyTaskTag(nextTag);
                      if (!policyTaskName.trim() || policyTaskName.includes('任务-')) {
                        setPolicyTaskName(
                          nextTag === 'risk_cruising'
                            ? `风险巡航任务-${policyTaskPolicyName || '策略'}`
                            : `资产侦查任务-${policyTaskPolicyName || '策略'}`
                        );
                      }
                    }}
                    className={UNIFIED_SELECT_CLASS}
                    disabled={policyTaskSubmitting}
                  >
                    <option value="task">资产侦查任务</option>
                    <option value="risk_cruising">风险巡航任务</option>
                  </select>
                  <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">任务名称</label>
                <input
                  value={policyTaskName}
                  onChange={(event) => setPolicyTaskName(event.target.value)}
                  disabled={policyTaskSubmitting}
                  className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
                  placeholder="请输入任务名称"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-brand-text-muted">目标</label>
                <textarea
                  value={policyTaskTarget}
                  onChange={(event) => setPolicyTaskTarget(event.target.value)}
                  disabled={policyTaskSubmitting}
                  className="w-full min-h-[180px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                  placeholder={
                    policyTaskTag === 'risk_cruising'
                      ? '请输入确定的目标，不会进行端口扫描,如: http://10.0.1.1:8081/ 10.0.1.1:2222'
                      : '请输入目标，支持IP、IP段、域名'
                  }
                />
                <p className="text-xs text-brand-text-muted">
                  {policyTaskTag === 'risk_cruising'
                    ? '请输入确定的目标，不会进行端口扫描,如: http://10.0.1.1:8081/ 10.0.1.1:2222'
                    : '请输入目标，支持IP、IP段、域名。支持一行一个。'}
                </p>
              </div>

              {policyTaskError ? (
                <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2">
                  {policyTaskError}
                </div>
              ) : null}

              <div className="flex justify-end gap-3">
                <button
                  onClick={closePolicyTaskDialog}
                  disabled={policyTaskSubmitting}
                  className="px-5 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition disabled:opacity-40"
                >
                  取消
                </button>
                <button
                  onClick={() => void submitPolicyTask()}
                  disabled={policyTaskSubmitting}
                  className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider"
                >
                  {policyTaskSubmitting ? '下发中...' : '确认下发'}
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {taskErrorDialog ? (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-5xl bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-brand-danger" />
                <h4 className="text-lg font-black">任务异常详情</h4>
              </div>
              <button
                onClick={() => setTaskErrorDialog(null)}
                className="p-2 rounded-lg hover:bg-brand-bg/70 transition"
                title="关闭"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-4 border-b border-brand-border bg-brand-bg/30 text-sm space-y-1">
              <div><span className="text-brand-text-muted">任务名：</span>{taskErrorDialog.taskName}</div>
              <div><span className="text-brand-text-muted">目标：</span><span className="font-mono break-all">{taskErrorDialog.target}</span></div>
              <div><span className="text-brand-text-muted">Task_ID：</span><span className="font-mono">{taskErrorDialog.taskId || '-'}</span></div>
            </div>

            <div className="p-6 max-h-[65vh] overflow-auto space-y-4">
              {taskErrorDialog.logs.length > 0 ? taskErrorDialog.logs.map((log, index) => (
                <div key={`${log.time}-${log.stage}-${index}`} className="rounded-xl border border-brand-border bg-brand-bg/40 p-4 space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <div><span className="text-brand-text-muted">时间：</span><span className="font-mono">{log.time || '-'}</span></div>
                    <div><span className="text-brand-text-muted">阶段：</span><span className="font-mono">{log.stage || '-'}</span></div>
                  </div>
                  <div className="text-sm">
                    <span className="text-brand-text-muted">异常说明：</span>
                    <div className="mt-1 whitespace-pre-wrap break-all leading-relaxed">{log.message || '-'}</div>
                  </div>
                  {log.traceback ? (
                    <div className="text-sm">
                      <span className="text-brand-text-muted">日志信息：</span>
                      <pre className="mt-1 whitespace-pre-wrap break-all leading-relaxed font-mono text-xs bg-brand-bg/70 border border-brand-border rounded-lg p-3 overflow-auto">{log.traceback}</pre>
                    </div>
                  ) : null}
                </div>
              )) : (
                <div className="text-sm text-brand-text-muted">
                  当前任务没有记录到详细异常日志（可能是历史任务或异常详情落库前的任务）。
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}

      {deleteConfirmDialog ? (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-brand-border flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <h4 className="text-lg font-black">{deleteConfirmDialog.title}</h4>
              </div>
              <button
                onClick={() => closeDeleteConfirmDialog(false)}
                className="p-2 rounded-lg hover:bg-brand-bg/70 transition"
                title="关闭"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-5">
              <p className="text-sm text-brand-text-muted whitespace-pre-wrap break-all leading-relaxed">
                {deleteConfirmDialog.message}
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => closeDeleteConfirmDialog(false)}
                  className="px-5 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition"
                >
                  取消
                </button>
                <button
                  onClick={() => closeDeleteConfirmDialog(true)}
                  className="px-5 py-2.5 rounded-xl bg-brand-danger text-white text-sm font-black hover:opacity-90 transition"
                >
                  {deleteConfirmDialog.confirmText}
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {screenshotPreview ? (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => setScreenshotPreview(null)}
        >
          <div
            className="w-full max-w-6xl bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="px-5 py-3 border-b border-brand-border flex items-center justify-between gap-3">
              <div className="text-sm font-semibold truncate">截图预览: {screenshotPreview.title}</div>
              <button
                type="button"
                onClick={() => setScreenshotPreview(null)}
                className="p-2 rounded-lg hover:bg-brand-bg/70 transition"
                title="关闭预览"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 max-h-[82vh] overflow-auto bg-brand-bg/40">
              <img
                src={screenshotPreview.url}
                alt={screenshotPreview.title}
                className="mx-auto max-w-full h-auto rounded-xl border border-brand-border bg-brand-bg"
              />
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ApiConsoleView({ token }: { token: string }) {
  type ServiceApiForm = {
    fofa_url: string;
    fofa_email: string;
    fofa_key: string;
    fofa_enable: boolean;
    certspotter_enable: boolean;
    hunter_api_key: string;
    hunter_enable: boolean;
    quake_token: string;
    quake_enable: boolean;
    zoomeye_api_key: string;
    zoomeye_enable: boolean;
    securitytrails_api_key: string;
    securitytrails_enable: boolean;
    virustotal_api_key: string;
    virustotal_enable: boolean;
    chaos_api_key: string;
    chaos_enable: boolean;
    passivetotal_email: string;
    passivetotal_key: string;
    passivetotal_enable: boolean;
    github_token: string;
  };

  type ServiceApiBoolKey =
    | 'fofa_enable'
    | 'certspotter_enable'
    | 'hunter_enable'
    | 'quake_enable'
    | 'zoomeye_enable'
    | 'securitytrails_enable'
    | 'virustotal_enable'
    | 'chaos_enable'
    | 'passivetotal_enable';

  type ServiceApiStringKey = Exclude<keyof ServiceApiForm, ServiceApiBoolKey>;

  const defaultForm: ServiceApiForm = {
    fofa_url: 'https://fofa.info',
    fofa_email: '',
    fofa_key: '',
    fofa_enable: true,
    certspotter_enable: true,
    hunter_api_key: '',
    hunter_enable: true,
    quake_token: '',
    quake_enable: true,
    zoomeye_api_key: '',
    zoomeye_enable: true,
    securitytrails_api_key: '',
    securitytrails_enable: false,
    virustotal_api_key: '',
    virustotal_enable: true,
    chaos_api_key: '',
    chaos_enable: false,
    passivetotal_email: '',
    passivetotal_key: '',
    passivetotal_enable: false,
    github_token: '',
  };

  const [configPath, setConfigPath] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [form, setForm] = useState<ServiceApiForm>(defaultForm);

  const normalizeForm = useCallback((rawValue: any): ServiceApiForm => {
    const raw = rawValue || {};
    return {
      fofa_url: String(raw.fofa_url || defaultForm.fofa_url),
      fofa_email: String(raw.fofa_email || ''),
      fofa_key: String(raw.fofa_key || ''),
      fofa_enable: raw.fofa_enable === undefined ? true : Boolean(raw.fofa_enable),
      certspotter_enable: raw.certspotter_enable === undefined ? true : Boolean(raw.certspotter_enable),
      hunter_api_key: String(raw.hunter_api_key || ''),
      hunter_enable: raw.hunter_enable === undefined ? true : Boolean(raw.hunter_enable),
      quake_token: String(raw.quake_token || ''),
      quake_enable: raw.quake_enable === undefined ? true : Boolean(raw.quake_enable),
      zoomeye_api_key: String(raw.zoomeye_api_key || ''),
      zoomeye_enable: raw.zoomeye_enable === undefined ? true : Boolean(raw.zoomeye_enable),
      securitytrails_api_key: String(raw.securitytrails_api_key || ''),
      securitytrails_enable: raw.securitytrails_enable === undefined ? false : Boolean(raw.securitytrails_enable),
      virustotal_api_key: String(raw.virustotal_api_key || ''),
      virustotal_enable: raw.virustotal_enable === undefined ? true : Boolean(raw.virustotal_enable),
      chaos_api_key: String(raw.chaos_api_key || ''),
      chaos_enable: raw.chaos_enable === undefined ? false : Boolean(raw.chaos_enable),
      passivetotal_email: String(raw.passivetotal_email || ''),
      passivetotal_key: String(raw.passivetotal_key || ''),
      passivetotal_enable: raw.passivetotal_enable === undefined ? false : Boolean(raw.passivetotal_enable),
      github_token: String(raw.github_token || ''),
    };
  }, []);

  const updateTextField = (key: ServiceApiStringKey, value: string) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const updateBoolField = (key: ServiceApiBoolKey, value: boolean) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const loadServiceApiConfig = useCallback(async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/service_api/', { method: 'GET' });
      const data = result?.data || {};
      setForm(normalizeForm(data?.service_api));
      setConfigPath(String(data.config_path || ''));
      setUpdatedAt(String(data.updated_at || ''));
    } catch (err: any) {
      setError(err?.message || '加载 API 配置失败');
    } finally {
      setLoading(false);
    }
  }, [token, normalizeForm]);

  useEffect(() => {
    void loadServiceApiConfig();
  }, [loadServiceApiConfig]);

  const saveServiceApiConfig = async () => {
    const normalizedUrl = form.fofa_url.trim();
    if (!normalizedUrl) {
      setError('FOFA URL 不能为空');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/service_api/', {
        method: 'POST',
        body: {
          service_api: {
            ...form,
            fofa_url: normalizedUrl,
            fofa_email: form.fofa_email.trim(),
            fofa_key: form.fofa_key.trim(),
            hunter_api_key: form.hunter_api_key.trim(),
            quake_token: form.quake_token.trim(),
            zoomeye_api_key: form.zoomeye_api_key.trim(),
            securitytrails_api_key: form.securitytrails_api_key.trim(),
            virustotal_api_key: form.virustotal_api_key.trim(),
            chaos_api_key: form.chaos_api_key.trim(),
            passivetotal_email: form.passivetotal_email.trim(),
            passivetotal_key: form.passivetotal_key.trim(),
            github_token: form.github_token.trim(),
          },
        },
      });

      const data = result?.data || {};
      setForm(normalizeForm(data?.service_api));
      setConfigPath(String(data.config_path || configPath));
      setUpdatedAt(String(data.saved_at || updatedAt));
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';
      setSuccess(`API 配置已保存${backupPath}`);
    } catch (err: any) {
      setError(err?.message || '保存 API 配置失败');
    } finally {
      setSaving(false);
    }
  };

  const providers: Array<{
    id: string;
    title: string;
    alias?: string;
    website?: string;
    enableKey?: ServiceApiBoolKey;
    enableLabel?: string;
    fields: Array<{
      key: ServiceApiStringKey;
      label: string;
      placeholder: string;
      hint?: string;
    }>;
  }> = [
    {
      id: 'fofa',
      title: 'FOFA',
      website: 'https://fofa.info/',
      enableKey: 'fofa_enable',
      enableLabel: '启用 FOFA 插件',
      fields: [
        { key: 'fofa_url', label: 'URL', placeholder: 'https://fofa.info', hint: 'FOFA.URL' },
        { key: 'fofa_email', label: '邮箱', placeholder: '请输入 FOFA 邮箱', hint: 'FOFA.EMAIL' },
        { key: 'fofa_key', label: 'KEY', placeholder: '请输入 FOFA KEY', hint: 'FOFA.KEY' },
      ],
    },
    {
      id: 'certspotter',
      title: 'certspotter',
      website: 'https://www.certspotter.com/',
      enableKey: 'certspotter_enable',
      enableLabel: '启用 certspotter 插件',
      fields: [],
    },
    {
      id: 'hunter',
      title: 'hunter_qax',
      alias: 'Hunter',
      website: 'https://hunter.qianxin.com/',
      enableKey: 'hunter_enable',
      enableLabel: '启用 Hunter 插件',
      fields: [
        { key: 'hunter_api_key', label: 'API KEY', placeholder: '请输入 Hunter API KEY', hint: 'QUERY_PLUGIN.hunter_qax.api_key' },
      ],
    },
    {
      id: 'quake',
      title: 'quake_360',
      alias: 'Quake360',
      website: 'https://quake.360.cn/',
      enableKey: 'quake_enable',
      enableLabel: '启用 Quake 插件',
      fields: [
        { key: 'quake_token', label: 'Token', placeholder: '请输入 Quake Token', hint: 'QUERY_PLUGIN.quake_360.quake_token' },
      ],
    },
    {
      id: 'zoomeye',
      title: 'Zoomeye',
      website: 'https://www.zoomeye.org/',
      enableKey: 'zoomeye_enable',
      enableLabel: '启用 Zoomeye 插件',
      fields: [
        { key: 'zoomeye_api_key', label: 'API KEY', placeholder: '请输入 Zoomeye API KEY', hint: 'QUERY_PLUGIN.zoomeye.api_key' },
      ],
    },
    {
      id: 'securitytrails',
      title: 'SecurityTrails',
      website: 'https://securitytrails.com/',
      enableKey: 'securitytrails_enable',
      enableLabel: '启用 SecurityTrails 插件',
      fields: [
        {
          key: 'securitytrails_api_key',
          label: 'API KEY',
          placeholder: '请输入 SecurityTrails API KEY',
          hint: 'QUERY_PLUGIN.securitytrails.api_key',
        },
      ],
    },
    {
      id: 'virustotal',
      title: 'virustotal',
      alias: 'VirusTotal',
      website: 'https://www.virustotal.com/gui/',
      enableKey: 'virustotal_enable',
      enableLabel: '启用 VirusTotal 插件',
      fields: [
        { key: 'virustotal_api_key', label: 'API KEY', placeholder: '请输入 VirusTotal API KEY', hint: 'QUERY_PLUGIN.virustotal.api_key' },
      ],
    },
    {
      id: 'chaos',
      title: 'Chaos',
      website: 'https://chaos.projectdiscovery.io/',
      enableKey: 'chaos_enable',
      enableLabel: '启用 Chaos 插件',
      fields: [
        { key: 'chaos_api_key', label: 'API KEY', placeholder: '请输入 Chaos API KEY', hint: 'QUERY_PLUGIN.chaos.api_key' },
      ],
    },
    {
      id: 'passivetotal',
      title: 'PassiveTotal',
      website: 'https://community.riskiq.com/',
      enableKey: 'passivetotal_enable',
      enableLabel: '启用 PassiveTotal 插件',
      fields: [
        {
          key: 'passivetotal_email',
          label: '邮箱',
          placeholder: '请输入 PassiveTotal 邮箱',
          hint: 'QUERY_PLUGIN.passivetotal.auth_email',
        },
        {
          key: 'passivetotal_key',
          label: 'KEY',
          placeholder: '请输入 PassiveTotal KEY',
          hint: 'QUERY_PLUGIN.passivetotal.auth_key',
        },
      ],
    },
    {
      id: 'github',
      title: 'GitHub',
      website: 'https://github.com/settings/tokens',
      fields: [
        { key: 'github_token', label: 'TOKEN', placeholder: '请输入 GitHub Personal Access Token', hint: 'GITHUB.TOKEN' },
      ],
    },
  ];

  return (
    <div className="p-8 space-y-6">
      <div>
        <h2 className="text-4xl font-black tracking-tight">API 管理</h2>
        <p className="text-brand-text-muted mt-2 text-sm">统一维护 FOFA、Hunter、Quake、Zoomeye 等第三方 API 配置并同步保存。</p>
      </div>

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-4">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="text-sm font-bold tracking-wide">API 凭据配置</div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadServiceApiConfig()}
              className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
              disabled={loading}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
            <button
              onClick={() => void saveServiceApiConfig()}
              className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition flex items-center gap-2 disabled:opacity-60"
              disabled={saving || loading}
            >
              <Settings className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
              {saving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
          <div className="bg-brand-bg/60 border border-brand-border rounded-xl px-3 py-2">
            <span className="text-brand-text-muted">配置文件:</span>
            <span className="font-mono ml-2">{configPath || '-'}</span>
          </div>
          <div className="bg-brand-bg/60 border border-brand-border rounded-xl px-3 py-2">
            <span className="text-brand-text-muted">最近更新时间:</span>
            <span className="font-mono ml-2">{updatedAt || '-'}</span>
          </div>
        </div>

        <div className="text-xs text-brand-text-muted bg-brand-bg/50 border border-brand-border rounded-xl px-3 py-2">
          提示：保存后会写入配置文件，建议重启 `web` 与 `worker` 容器让 API 插件配置立即生效。
        </div>

        {error ? <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">{error}</div> : null}
        {success ? <div className="text-xs text-emerald-400 bg-emerald-400/10 border border-emerald-400/30 rounded-lg px-3 py-2">{success}</div> : null}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {providers.map((provider) => (
          <div key={provider.id} className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-sm font-black tracking-wide break-all">
                  {provider.title}
                  {provider.alias ? <span className="ml-2 text-brand-text-muted font-semibold">({provider.alias})</span> : null}
                </h3>
                {provider.website ? (
                  <a
                    href={provider.website}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-brand-accent hover:underline break-all font-mono"
                    title={provider.website}
                  >
                    {provider.website}
                  </a>
                ) : null}
              </div>
              {provider.enableKey ? (
                <label className="flex items-center gap-2 text-xs text-brand-text-muted shrink-0">
                  <input
                    type="checkbox"
                    checked={Boolean(form[provider.enableKey])}
                    onChange={(event) => updateBoolField(provider.enableKey, event.target.checked)}
                    className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
                  />
                  <span>{provider.enableLabel}</span>
                </label>
              ) : null}
            </div>

            <div className="space-y-3">
              {provider.fields.length === 0 ? (
                <div className="text-xs text-brand-text-muted bg-brand-bg/40 border border-brand-border rounded-xl px-3 py-2">
                  当前插件无需配置 API Key。
                </div>
              ) : null}
              {provider.fields.map((field) => (
                <div key={field.key} className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted block">
                    {field.label}
                    {field.hint ? <span className="ml-2 font-mono opacity-70">{field.hint}</span> : null}
                  </label>
                  <input
                    value={String(form[field.key] || '')}
                    onChange={(event) => updateTextField(field.key, event.target.value)}
                    className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
                    placeholder={field.placeholder}
                  />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConfigConsoleView({ token }: { token: string }) {
  const nucleiTimeoutPresets = [
    { id: 'low', label: '2核2G 低速', hours: 1, value: 3600 },
    { id: 'medium', label: '4核4G 中速', hours: 2, value: 7200 },
    { id: 'high', label: '8核16G 快速', hours: 3, value: 10800 },
  ];

  type DomainDictOption = {
    label: string;
    path: string;
    source: string;
    exists: boolean;
    size: number;
    selected?: boolean;
  };

  const [configPath, setConfigPath] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [domainUploading, setDomainUploading] = useState(false);
  const [fileLeakUploading, setFileLeakUploading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [domainDictOptions, setDomainDictOptions] = useState<DomainDictOption[]>([]);
  const [fileLeakDictOptions, setFileLeakDictOptions] = useState<DomainDictOption[]>([]);
  const [uploadDomainFile, setUploadDomainFile] = useState<File | null>(null);
  const [uploadFileLeakFile, setUploadFileLeakFile] = useState<File | null>(null);
  const domainUploadInputRef = useRef<HTMLInputElement | null>(null);
  const fileLeakUploadInputRef = useRef<HTMLInputElement | null>(null);

  const [domainDict, setDomainDict] = useState('');
  const [fileLeakDict, setFileLeakDict] = useState('');
  const [domainBruteConcurrent, setDomainBruteConcurrent] = useState(180);
  const [altDnsConcurrent, setAltDnsConcurrent] = useState(800);
  const [webGunicornWorkers, setWebGunicornWorkers] = useState(2);
  const [celeryTaskWorkerConcurrency, setCeleryTaskWorkerConcurrency] = useState(2);
  const [celeryGithubWorkerConcurrency, setCeleryGithubWorkerConcurrency] = useState(1);
  const [celeryPrefetchMultiplier, setCeleryPrefetchMultiplier] = useState(1);
  const [celeryMaxTasksPerChild, setCeleryMaxTasksPerChild] = useState(20);
  const [celeryMaxMemoryPerChild, setCeleryMaxMemoryPerChild] = useState(280000);
  const [nucleiSingleTargetTimeoutSec, setNucleiSingleTargetTimeoutSec] = useState(3600);
  const [blackIpsText, setBlackIpsText] = useState('');
  const [dnsResolversText, setDnsResolversText] = useState('');

  const splitTextList = (rawText: string) =>
    rawText
      .replace(/,/g, '\n')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '');

  const loadScanConfig = useCallback(async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/scan_config/', { method: 'GET' });
      const data = result?.data || {};
      const scanConfig = data?.scan_config || {};
      const nextDomainOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
      const nextFileLeakOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];

      setDomainDict(String(scanConfig.domain_dict || ''));
      setFileLeakDict(String(scanConfig.file_leak_dict || ''));
      setDomainBruteConcurrent(Number(scanConfig.domain_brute_concurrent || 180));
      setAltDnsConcurrent(Number(scanConfig.alt_dns_concurrent || 800));
      setWebGunicornWorkers(Number(scanConfig.web_gunicorn_workers || 2));
      setCeleryTaskWorkerConcurrency(Number(scanConfig.celery_task_worker_concurrency || 2));
      setCeleryGithubWorkerConcurrency(Number(scanConfig.celery_github_worker_concurrency || 1));
      setCeleryPrefetchMultiplier(Number(scanConfig.celery_prefetch_multiplier || 1));
      setCeleryMaxTasksPerChild(Number(scanConfig.celery_max_tasks_per_child || 20));
      setCeleryMaxMemoryPerChild(Number(scanConfig.celery_max_memory_per_child || 280000));
      setNucleiSingleTargetTimeoutSec(Number(scanConfig.nuclei_single_target_timeout_sec || 3600));
      setBlackIpsText(Array.isArray(scanConfig.black_ips) ? scanConfig.black_ips.join('\n') : '');
      setDnsResolversText(Array.isArray(scanConfig.dns_resolvers) ? scanConfig.dns_resolvers.join('\n') : '');

      setDomainDictOptions(nextDomainOptions);
      setFileLeakDictOptions(nextFileLeakOptions);
      setConfigPath(String(data.config_path || ''));
      setUpdatedAt(String(data.updated_at || ''));
    } catch (err: any) {
      setError(err?.message || '加载扫描配置失败');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void loadScanConfig();
  }, [loadScanConfig]);

  const saveScanConfig = async () => {
    const normalizedDomainDict = domainDict.trim();
    if (!normalizedDomainDict) {
      setError('请先选择域名爆破字典');
      return;
    }
    const normalizedFileLeakDict = fileLeakDict.trim();
    if (!normalizedFileLeakDict) {
      setError('请先选择敏感文件泄漏字典');
      return;
    }

    if (!Number.isFinite(domainBruteConcurrent) || domainBruteConcurrent <= 0) {
      setError('域名爆破并发数必须大于 0');
      return;
    }

    if (!Number.isFinite(altDnsConcurrent) || altDnsConcurrent <= 0) {
      setError('组合生成域名爆破并发数必须大于 0');
      return;
    }
    if (!Number.isFinite(webGunicornWorkers) || webGunicornWorkers <= 0) {
      setError('Web 进程并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryTaskWorkerConcurrency) || celeryTaskWorkerConcurrency <= 0) {
      setError('Celery 主队列并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryGithubWorkerConcurrency) || celeryGithubWorkerConcurrency <= 0) {
      setError('Celery GitHub 队列并发必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryPrefetchMultiplier) || celeryPrefetchMultiplier <= 0) {
      setError('Celery 预取倍率必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryMaxTasksPerChild) || celeryMaxTasksPerChild <= 0) {
      setError('Celery 子进程任务上限必须大于 0');
      return;
    }
    if (!Number.isFinite(celeryMaxMemoryPerChild) || celeryMaxMemoryPerChild <= 0) {
      setError('Celery 子进程内存上限必须大于 0');
      return;
    }
    if (!Number.isFinite(nucleiSingleTargetTimeoutSec) || nucleiSingleTargetTimeoutSec <= 0) {
      setError('Nuclei 单目标最大扫描时间必须大于 0');
      return;
    }

    const blackIps = splitTextList(blackIpsText);
    if (blackIps.length === 0) {
      setError('黑名单IP配置不能为空');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/api_console/scan_config/', {
        method: 'POST',
        body: {
          scan_config: {
            domain_dict: normalizedDomainDict,
            file_leak_dict: normalizedFileLeakDict,
            domain_brute_concurrent: Math.floor(domainBruteConcurrent),
            alt_dns_concurrent: Math.floor(altDnsConcurrent),
            web_gunicorn_workers: Math.floor(webGunicornWorkers),
            celery_task_worker_concurrency: Math.floor(celeryTaskWorkerConcurrency),
            celery_github_worker_concurrency: Math.floor(celeryGithubWorkerConcurrency),
            celery_prefetch_multiplier: Math.floor(celeryPrefetchMultiplier),
            celery_max_tasks_per_child: Math.floor(celeryMaxTasksPerChild),
            celery_max_memory_per_child: Math.floor(celeryMaxMemoryPerChild),
            nuclei_single_target_timeout_sec: Math.floor(nucleiSingleTargetTimeoutSec),
            black_ips: blackIps,
            dns_resolvers: splitTextList(dnsResolversText),
          },
        },
      });

      const data = result?.data || {};
      const savedConfig = data?.scan_config || {};
      const nextDomainOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
      const nextFileLeakOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';

      setDomainDict(String(savedConfig.domain_dict || normalizedDomainDict));
      setFileLeakDict(String(savedConfig.file_leak_dict || normalizedFileLeakDict));
      setDomainBruteConcurrent(Number(savedConfig.domain_brute_concurrent || domainBruteConcurrent));
      setAltDnsConcurrent(Number(savedConfig.alt_dns_concurrent || altDnsConcurrent));
      setWebGunicornWorkers(Number(savedConfig.web_gunicorn_workers || webGunicornWorkers));
      setCeleryTaskWorkerConcurrency(Number(savedConfig.celery_task_worker_concurrency || celeryTaskWorkerConcurrency));
      setCeleryGithubWorkerConcurrency(Number(savedConfig.celery_github_worker_concurrency || celeryGithubWorkerConcurrency));
      setCeleryPrefetchMultiplier(Number(savedConfig.celery_prefetch_multiplier || celeryPrefetchMultiplier));
      setCeleryMaxTasksPerChild(Number(savedConfig.celery_max_tasks_per_child || celeryMaxTasksPerChild));
      setCeleryMaxMemoryPerChild(Number(savedConfig.celery_max_memory_per_child || celeryMaxMemoryPerChild));
      setNucleiSingleTargetTimeoutSec(Number(savedConfig.nuclei_single_target_timeout_sec || nucleiSingleTargetTimeoutSec));
      setBlackIpsText(Array.isArray(savedConfig.black_ips) ? savedConfig.black_ips.join('\n') : blackIpsText);
      setDnsResolversText(Array.isArray(savedConfig.dns_resolvers) ? savedConfig.dns_resolvers.join('\n') : dnsResolversText);

      setDomainDictOptions(nextDomainOptions);
      setFileLeakDictOptions(nextFileLeakOptions);
      setConfigPath(String(data.config_path || configPath));
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`扫描配置已保存${backupPath}`);
    } catch (err: any) {
      setError(err?.message || '保存扫描配置失败');
    } finally {
      setSaving(false);
    }
  };

  const uploadDomainDict = async () => {
    if (!uploadDomainFile) {
      setError('请先选择要上传的字典文件');
      return;
    }

    setDomainUploading(true);
    setError('');
    setSuccess('');
    try {
      const formData = new FormData();
      formData.append('file', uploadDomainFile);
      const result = await requestApi(token, '/api_console/scan_config/domain_dict/upload/', {
        method: 'POST',
        body: formData,
      });
      const data = result?.data || {};
      const uploadedPath = String(data?.domain_dict_path || '');
      const nextOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];

      if (uploadedPath) {
        setDomainDict(uploadedPath);
      }
      setDomainDictOptions(nextOptions);
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`字典上传成功: ${uploadDomainFile.name}`);

      setUploadDomainFile(null);
      if (domainUploadInputRef.current) {
        domainUploadInputRef.current.value = '';
      }
    } catch (err: any) {
      setError(err?.message || '字典上传失败');
    } finally {
      setDomainUploading(false);
    }
  };

  const uploadFileLeakDict = async () => {
    if (!uploadFileLeakFile) {
      setError('请先选择要上传的字典文件');
      return;
    }

    setFileLeakUploading(true);
    setError('');
    setSuccess('');
    try {
      const formData = new FormData();
      formData.append('file', uploadFileLeakFile);
      const result = await requestApi(token, '/api_console/scan_config/file_leak_dict/upload/', {
        method: 'POST',
        body: formData,
      });
      const data = result?.data || {};
      const uploadedPath = String(data?.file_leak_dict_path || '');
      const nextOptions = Array.isArray(data?.available_file_leak_dicts) ? data.available_file_leak_dicts : [];

      if (uploadedPath) {
        setFileLeakDict(uploadedPath);
      }
      setFileLeakDictOptions(nextOptions);
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`字典上传成功: ${uploadFileLeakFile.name}`);

      setUploadFileLeakFile(null);
      if (fileLeakUploadInputRef.current) {
        fileLeakUploadInputRef.current.value = '';
      }
    } catch (err: any) {
      setError(err?.message || '字典上传失败');
    } finally {
      setFileLeakUploading(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h2 className="text-4xl font-black tracking-tight">配置管理</h2>
        <p className="text-brand-text-muted mt-2 text-sm">支持配置域名爆破字典、敏感文件泄漏字典、扫描并发、Nuclei 单目标超时、Web/Celery 运行并发、黑名单IP与域名解析器，写入 config-docker.yaml 并可在重启后生效。</p>
      </div>

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-4">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="text-sm font-bold tracking-wide">扫描配置</div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadScanConfig()}
              className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
              disabled={loading}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
            <button
              onClick={() => void saveScanConfig()}
              className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition flex items-center gap-2 disabled:opacity-60"
              disabled={saving || loading || domainUploading || fileLeakUploading}
            >
              <Settings className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
              {saving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
          <div className="bg-brand-bg/60 border border-brand-border rounded-xl px-3 py-2">
            <span className="text-brand-text-muted">配置文件:</span>
            <span className="font-mono ml-2">{configPath || '-'}</span>
          </div>
          <div className="bg-brand-bg/60 border border-brand-border rounded-xl px-3 py-2">
            <span className="text-brand-text-muted">最近更新时间:</span>
            <span className="font-mono ml-2">{updatedAt || '-'}</span>
          </div>
        </div>

        <div className="text-xs text-brand-text-muted bg-brand-bg/50 border border-brand-border rounded-xl px-3 py-2">
          提示：保存后会写入配置文件，建议重启 `web` 与 `worker` 容器让扫描参数完全生效。
        </div>

        {error ? <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">{error}</div> : null}
        {success ? <div className="text-xs text-emerald-400 bg-emerald-400/10 border border-emerald-400/30 rounded-lg px-3 py-2">{success}</div> : null}
      </div>

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-5">
        <div className="space-y-2">
          <label className="text-xs font-bold text-brand-text-muted block">
            域名爆破字典
            <span className="ml-2 font-mono opacity-70">ARL.DOMAIN_DICT</span>
          </label>
          <div className="relative">
            <select
              value={domainDict}
              onChange={(event) => setDomainDict(event.target.value)}
              className={UNIFIED_SELECT_CLASS}
            >
              <option value="">请选择字典文件</option>
              {domainDictOptions.map((item) => (
                <option key={item.path} value={item.path}>
                  {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-brand-text-muted block">上传新字典（.txt）</label>
          <div className="flex flex-col lg:flex-row gap-2">
            <input
              ref={domainUploadInputRef}
              type="file"
              accept=".txt"
              className="flex-1 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
              onChange={(event) => {
                const file = event.target.files?.[0];
                setUploadDomainFile(file || null);
              }}
            />
            <button
              onClick={() => void uploadDomainDict()}
              className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center justify-center gap-2 disabled:opacity-60"
              disabled={domainUploading || loading || saving}
            >
              <Upload className={`w-4 h-4 ${domainUploading ? 'animate-spin' : ''}`} />
              {domainUploading ? '上传中...' : '上传字典'}
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-brand-text-muted block">
            敏感文件泄漏字典
            <span className="ml-2 font-mono opacity-70">ARL.FILE_LEAK_DICT</span>
          </label>
          <div className="relative">
            <select
              value={fileLeakDict}
              onChange={(event) => setFileLeakDict(event.target.value)}
              className={UNIFIED_SELECT_CLASS}
            >
              <option value="">请选择字典文件</option>
              {fileLeakDictOptions.map((item) => (
                <option key={item.path} value={item.path}>
                  {item.label} [{item.source}] {item.exists ? '' : '(文件不存在)'}
                </option>
              ))}
            </select>
            <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-brand-text-muted block">上传敏感文件字典（.txt）</label>
          <div className="flex flex-col lg:flex-row gap-2">
            <input
              ref={fileLeakUploadInputRef}
              type="file"
              accept=".txt"
              className="flex-1 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
              onChange={(event) => {
                const file = event.target.files?.[0];
                setUploadFileLeakFile(file || null);
              }}
            />
            <button
              onClick={() => void uploadFileLeakDict()}
              className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center justify-center gap-2 disabled:opacity-60"
              disabled={fileLeakUploading || loading || saving}
            >
              <Upload className={`w-4 h-4 ${fileLeakUploading ? 'animate-spin' : ''}`} />
              {fileLeakUploading ? '上传中...' : '上传字典'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              域名爆破并发数
              <span className="ml-2 font-mono opacity-70">ARL.DOMAIN_BRUTE_CONCURRENT</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(domainBruteConcurrent)}
              onChange={(event) => setDomainBruteConcurrent(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              组合生成域名爆破并发数
              <span className="ml-2 font-mono opacity-70">ARL.ALT_DNS_CONCURRENT</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(altDnsConcurrent)}
              onChange={(event) => setAltDnsConcurrent(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Web 进程并发
              <span className="ml-2 font-mono opacity-70">ARL.WEB_GUNICORN_WORKERS</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(webGunicornWorkers)}
              onChange={(event) => setWebGunicornWorkers(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Celery 主队列并发
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_TASK_WORKER_CONCURRENCY</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(celeryTaskWorkerConcurrency)}
              onChange={(event) => setCeleryTaskWorkerConcurrency(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Celery GitHub 队列并发
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_GITHUB_WORKER_CONCURRENCY</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(celeryGithubWorkerConcurrency)}
              onChange={(event) => setCeleryGithubWorkerConcurrency(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Celery 预取倍率
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_PREFETCH_MULTIPLIER</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(celeryPrefetchMultiplier)}
              onChange={(event) => setCeleryPrefetchMultiplier(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Celery 子进程任务上限
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_MAX_TASKS_PER_CHILD</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(celeryMaxTasksPerChild)}
              onChange={(event) => setCeleryMaxTasksPerChild(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Celery 子进程内存上限(KB)
              <span className="ml-2 font-mono opacity-70">ARL.CELERY_MAX_MEMORY_PER_CHILD</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(celeryMaxMemoryPerChild)}
              onChange={(event) => setCeleryMaxMemoryPerChild(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>
        </div>

        <div className="space-y-3 rounded-xl border border-brand-border bg-brand-bg/35 p-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              Nuclei 单个目标最多扫描时间（秒）
              <span className="ml-2 font-mono opacity-70">ARL.NUCLEI_SINGLE_TARGET_TIMEOUT_SEC</span>
            </label>
            <input
              type="number"
              min={60}
              value={String(nucleiSingleTargetTimeoutSec)}
              onChange={(event) => setNucleiSingleTargetTimeoutSec(Number(event.target.value || 0))}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>

          <div className="flex flex-wrap gap-2">
            {nucleiTimeoutPresets.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setNucleiSingleTargetTimeoutSec(item.value)}
                className={`px-3 py-1.5 rounded-lg border text-xs font-semibold transition ${
                  nucleiSingleTargetTimeoutSec === item.value
                    ? 'border-brand-accent bg-brand-accent/15 text-brand-accent'
                    : 'border-brand-border hover:bg-brand-bg/70'
                }`}
              >
                {item.label}（{item.hours}小时）
              </button>
            ))}
          </div>

          <div className="text-xs text-brand-text-muted">
            推荐档位：2核2G=1小时，4核4G=2小时，8核16G=3小时。当前配置约 {(nucleiSingleTargetTimeoutSec / 3600).toFixed(2)} 小时/目标。
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              黑名单IP配置
              <span className="ml-2 font-mono opacity-70">ARL.BLACK_IPS</span>
            </label>
            <textarea
              value={blackIpsText}
              onChange={(event) => setBlackIpsText(event.target.value)}
              className="w-full min-h-[120px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
              placeholder="每行一个IP段，例如 127.0.0.0/8"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              域名解析器配置
              <span className="ml-2 font-mono opacity-70">ARL.DNS_RESOLVERS</span>
            </label>
            <textarea
              value={dnsResolversText}
              onChange={(event) => setDnsResolversText(event.target.value)}
              className="w-full min-h-[120px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
              placeholder="每行一个DNS解析器，例如 223.5.5.5 或 1.1.1.1:53"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function DingtalkIntegrationView({ token }: { token: string }) {
  type DingtalkConfigForm = {
    dingding_access_token: string;
    dingding_secret: string;
    kb_enable: boolean;
    ssl_cert_notify_enable: boolean;
    ssl_cert_notify_days: number;
    base_url: string;
    corp_id: string;
    app_key: string;
    app_secret: string;
    operator_id: string;
    workspace_id: string;
    parent_node_id: string;
    create_node_path: string;
    kb_timeout: number;
    title_prefix: string;
    report_base_url: string;
  };

  type DingtalkBoolKey = 'kb_enable' | 'ssl_cert_notify_enable';
  type DingtalkStringKey = Exclude<keyof DingtalkConfigForm, DingtalkBoolKey | 'kb_timeout' | 'ssl_cert_notify_days'>;

  const defaultForm: DingtalkConfigForm = {
    dingding_access_token: '',
    dingding_secret: '',
    kb_enable: false,
    ssl_cert_notify_enable: false,
    ssl_cert_notify_days: 30,
    base_url: 'https://api.dingtalk.com',
    corp_id: '',
    app_key: '',
    app_secret: '',
    operator_id: '',
    workspace_id: '',
    parent_node_id: '',
    create_node_path: '/v1.0/doc/workspaces/{workspace_id}/docs',
    kb_timeout: 20,
    title_prefix: '互联网资产自动化收集',
    report_base_url: '',
  };

  const [form, setForm] = useState<DingtalkConfigForm>(defaultForm);
  const [runtimeStatus, setRuntimeStatus] = useState<any>({});
  const [configPath, setConfigPath] = useState('');
  const [updatedAt, setUpdatedAt] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [loadingWorkspaces, setLoadingWorkspaces] = useState(false);
  const [loadingNodes, setLoadingNodes] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [debugResult, setDebugResult] = useState('');

  const normalizeForm = useCallback((rawValue: any): DingtalkConfigForm => {
    const raw = rawValue || {};
    const parsedNotifyDays = Number(raw.ssl_cert_notify_days || 30);
    const safeNotifyDays = Number.isFinite(parsedNotifyDays) && parsedNotifyDays > 0 ? parsedNotifyDays : 30;
    return {
      dingding_access_token: String(raw.dingding_access_token || ''),
      dingding_secret: String(raw.dingding_secret || ''),
      kb_enable: Boolean(raw.kb_enable),
      ssl_cert_notify_enable: Boolean(raw.ssl_cert_notify_enable),
      ssl_cert_notify_days: safeNotifyDays,
      base_url: String(raw.base_url || 'https://api.dingtalk.com'),
      corp_id: String(raw.corp_id || ''),
      app_key: String(raw.app_key || ''),
      app_secret: String(raw.app_secret || ''),
      operator_id: String(raw.operator_id || ''),
      workspace_id: String(raw.workspace_id || ''),
      parent_node_id: String(raw.parent_node_id || ''),
      create_node_path: String(raw.create_node_path || '/v1.0/doc/workspaces/{workspace_id}/docs'),
      kb_timeout: Number(raw.kb_timeout || 20),
      title_prefix: String(raw.title_prefix || '互联网资产自动化收集'),
      report_base_url: String(raw.report_base_url || ''),
    };
  }, []);

  const loadDingtalkConfig = useCallback(async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/config/', { method: 'GET' });
      const data = result?.data || {};
      setForm(normalizeForm(data?.config));
      setRuntimeStatus(data?.runtime_status || {});
      setConfigPath(String(data.config_path || ''));
      setUpdatedAt(String(data.updated_at || ''));
    } catch (err: any) {
      setError(err?.message || '加载钉钉集成配置失败');
    } finally {
      setLoading(false);
    }
  }, [token, normalizeForm]);

  useEffect(() => {
    void loadDingtalkConfig();
  }, [loadDingtalkConfig]);

  const updateStringField = (key: DingtalkStringKey, value: string) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const updateBoolField = (key: DingtalkBoolKey, value: boolean) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const updateTimeout = (value: string) => {
    setForm((prev) => ({ ...prev, kb_timeout: Number(value || 0) }));
  };

  const updateSslNotifyDays = (value: string) => {
    setForm((prev) => ({ ...prev, ssl_cert_notify_days: Number(value || 0) }));
  };

  const saveDingtalkConfig = async () => {
    if (!form.base_url.trim()) {
      setError('钉钉 OpenAPI 地址不能为空');
      return;
    }
    if (!Number.isFinite(form.kb_timeout) || form.kb_timeout <= 0) {
      setError('知识库超时时间必须大于 0');
      return;
    }
    if (!Number.isFinite(form.ssl_cert_notify_days) || form.ssl_cert_notify_days <= 0) {
      setError('SSL证书提醒天数必须大于 0');
      return;
    }

    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/config/', {
        method: 'POST',
        body: {
          dingtalk_config: {
            ...form,
            dingding_access_token: form.dingding_access_token.trim(),
            dingding_secret: form.dingding_secret.trim(),
            base_url: form.base_url.trim(),
            corp_id: form.corp_id.trim(),
            app_key: form.app_key.trim(),
            app_secret: form.app_secret.trim(),
            operator_id: form.operator_id.trim(),
            workspace_id: form.workspace_id.trim(),
            parent_node_id: form.parent_node_id.trim(),
            create_node_path: form.create_node_path.trim(),
            kb_timeout: Math.floor(form.kb_timeout),
            ssl_cert_notify_days: Math.floor(form.ssl_cert_notify_days),
            title_prefix: form.title_prefix.trim(),
            report_base_url: form.report_base_url.trim(),
          },
        },
      });
      const data = result?.data || {};
      setForm(normalizeForm(data?.config));
      setRuntimeStatus(data?.runtime_status || {});
      setConfigPath(String(data.config_path || configPath));
      setUpdatedAt(String(data.saved_at || updatedAt));
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';
      setSuccess(`钉钉集成配置已保存${backupPath}`);
    } catch (err: any) {
      setError(err?.message || '保存钉钉集成配置失败');
    } finally {
      setSaving(false);
    }
  };

  const runDingtalkTest = async () => {
    setTesting(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/test/', {
        method: 'POST',
        body: { force_refresh_token: true },
      });
      setDebugResult(JSON.stringify(result?.data || {}, null, 2));
      setSuccess('钉钉连通性测试完成');
    } catch (err: any) {
      setError(err?.message || '钉钉连通性测试失败');
    } finally {
      setTesting(false);
    }
  };

  const loadWorkspaces = async () => {
    setLoadingWorkspaces(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/workspaces/', {
        method: 'POST',
        body: { operator_id: form.operator_id.trim() },
      });
      setDebugResult(JSON.stringify(result?.data || {}, null, 2));
      setSuccess('空间列表获取成功');
    } catch (err: any) {
      setError(err?.message || '获取空间列表失败');
    } finally {
      setLoadingWorkspaces(false);
    }
  };

  const loadNodes = async () => {
    setLoadingNodes(true);
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/dingtalk_api/nodes/', {
        method: 'POST',
        body: {
          operator_id: form.operator_id.trim(),
          parent_node_id: form.parent_node_id.trim(),
        },
      });
      setDebugResult(JSON.stringify(result?.data || {}, null, 2));
      setSuccess('节点列表获取成功');
    } catch (err: any) {
      setError(err?.message || '获取节点列表失败');
    } finally {
      setLoadingNodes(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h2 className="text-4xl font-black tracking-tight">钉钉集成</h2>
        <p className="text-brand-text-muted mt-2 text-sm">
          在浏览器中维护钉钉机器人与知识库配置，保存后写入 config-docker.yaml，支持资产报告链接等参数统一管理。
        </p>
      </div>

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-4">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="text-sm font-bold tracking-wide">配置状态</div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadDingtalkConfig()}
              className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
              disabled={loading}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              重新加载
            </button>
            <button
              onClick={() => void saveDingtalkConfig()}
              className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition flex items-center gap-2 disabled:opacity-60"
              disabled={saving || loading}
            >
              <Settings className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
              {saving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
          <div className="bg-brand-bg/60 border border-brand-border rounded-xl px-3 py-2">
            <span className="text-brand-text-muted">配置文件:</span>
            <span className="font-mono ml-2">{configPath || '-'}</span>
          </div>
          <div className="bg-brand-bg/60 border border-brand-border rounded-xl px-3 py-2">
            <span className="text-brand-text-muted">最近更新时间:</span>
            <span className="font-mono ml-2">{updatedAt || '-'}</span>
          </div>
        </div>

        <div className="text-xs text-brand-text-muted bg-brand-bg/50 border border-brand-border rounded-xl px-3 py-2">
          提示：保存后 `web` 端调试会立即生效；扫描任务通知建议重启 `worker` 容器后完全生效。
        </div>

        {error ? <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">{error}</div> : null}
        {success ? <div className="text-xs text-emerald-400 bg-emerald-400/10 border border-emerald-400/30 rounded-lg px-3 py-2">{success}</div> : null}
      </div>

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-5">
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              钉钉机器人 Token
              <span className="ml-2 font-mono opacity-70">DINGDING.ACCESS_TOKEN</span>
            </label>
            <input
              value={form.dingding_access_token}
              onChange={(event) => updateStringField('dingding_access_token', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
              placeholder="用于群机器人通知"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              钉钉机器人 Secret
              <span className="ml-2 font-mono opacity-70">DINGDING.SECRET</span>
            </label>
            <input
              value={form.dingding_secret}
              onChange={(event) => updateStringField('dingding_secret', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
              placeholder="机器人加签密钥（可选）"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={form.kb_enable}
              onChange={(event) => updateBoolField('kb_enable', event.target.checked)}
              className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
            />
            <span className="font-medium">启用知识库推送</span>
          </label>
          <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={form.ssl_cert_notify_enable}
              onChange={(event) => updateBoolField('ssl_cert_notify_enable', event.target.checked)}
              className="h-4 w-4 cursor-pointer rounded border border-brand-border bg-brand-bg"
            />
            <span className="font-medium">SSL证书过期通知</span>
          </label>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              SSL提醒天数
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.SSL_CERT_NOTIFY_DAYS</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(form.ssl_cert_notify_days)}
              onChange={(event) => updateSslNotifyDays(event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              API 超时时间(秒)
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.KB_TIMEOUT</span>
            </label>
            <input
              type="number"
              min={1}
              value={String(form.kb_timeout)}
              onChange={(event) => updateTimeout(event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              OpenAPI 地址
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.BASE_URL</span>
            </label>
            <input
              value={form.base_url}
              onChange={(event) => updateStringField('base_url', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
              placeholder="https://api.dingtalk.com"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              资产结果访问地址
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.REPORT_BASE_URL</span>
            </label>
            <input
              value={form.report_base_url}
              onChange={(event) => updateStringField('report_base_url', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
              placeholder="如: https://arl.example.com"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              CorpID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.CORP_ID</span>
            </label>
            <input
              value={form.corp_id}
              onChange={(event) => updateStringField('corp_id', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              AppKey
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.APP_KEY</span>
            </label>
            <input
              value={form.app_key}
              onChange={(event) => updateStringField('app_key', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              AppSecret
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.APP_SECRET</span>
            </label>
            <input
              value={form.app_secret}
              onChange={(event) => updateStringField('app_secret', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              操作者ID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.OPERATOR_ID</span>
            </label>
            <input
              value={form.operator_id}
              onChange={(event) => updateStringField('operator_id', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              工作空间ID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.WORKSPACE_ID</span>
            </label>
            <input
              value={form.workspace_id}
              onChange={(event) => updateStringField('workspace_id', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              父节点ID
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.PARENT_NODE_ID</span>
            </label>
            <input
              value={form.parent_node_id}
              onChange={(event) => updateStringField('parent_node_id', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              创建文档接口路径
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.CREATE_NODE_PATH</span>
            </label>
            <input
              value={form.create_node_path}
              onChange={(event) => updateStringField('create_node_path', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-bold text-brand-text-muted block">
              报告标题前缀
              <span className="ml-2 font-mono opacity-70">DINGTALK_API.TITLE_PREFIX</span>
            </label>
            <input
              value={form.title_prefix}
              onChange={(event) => updateStringField('title_prefix', event.target.value)}
              className="w-full rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
            />
          </div>
        </div>
      </div>

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => void runDingtalkTest()}
            className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition disabled:opacity-60 flex items-center gap-2"
            disabled={testing || loading}
          >
            <Play className={`w-4 h-4 ${testing ? 'animate-spin' : ''}`} />
            {testing ? '测试中...' : '测试连通性'}
          </button>
          <button
            onClick={() => void loadWorkspaces()}
            className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition disabled:opacity-60 flex items-center gap-2"
            disabled={loadingWorkspaces || loading}
          >
            <Globe className={`w-4 h-4 ${loadingWorkspaces ? 'animate-spin' : ''}`} />
            获取空间列表
          </button>
          <button
            onClick={() => void loadNodes()}
            className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition disabled:opacity-60 flex items-center gap-2"
            disabled={loadingNodes || loading}
          >
            <Database className={`w-4 h-4 ${loadingNodes ? 'animate-spin' : ''}`} />
            获取节点列表
          </button>
        </div>

        <div className="text-xs text-brand-text-muted bg-brand-bg/50 border border-brand-border rounded-xl px-3 py-2">
          运行状态：缺失基础字段 {Array.isArray(runtimeStatus?.missing_basic_fields) ? runtimeStatus.missing_basic_fields.join(', ') || '无' : '无'}；
          缺失发布字段 {Array.isArray(runtimeStatus?.missing_publish_fields) ? runtimeStatus.missing_publish_fields.join(', ') || '无' : '无'}
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-brand-text-muted block">调试输出</label>
          <textarea
            value={debugResult}
            readOnly
            className="w-full min-h-[220px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm font-mono"
            placeholder="点击测试按钮后显示返回结果"
          />
        </div>
      </div>
    </div>
  );
}

function MainShell() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [username, setUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || 'admin');
  const [activeModuleId, setActiveModuleId] = useState(() => resolveStoredModuleId(localStorage.getItem(ACTIVE_MODULE_KEY)));
  const [moduleExternalFilters, setModuleExternalFilters] = useState<Record<string, JsonValue>>({});
  const [globalAction, setGlobalAction] = useState<ModuleAction | null>(null);
  const [globalActionPayload, setGlobalActionPayload] = useState<JsonValue>({});
  const [globalNotice, setGlobalNotice] = useState('');
  const [loginError, setLoginError] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);
  const [passwdDialogOpen, setPasswdDialogOpen] = useState(false);
  const [passwdForm, setPasswdForm] = useState({ old_password: '', new_password: '', check_password: '' });
  const [passwdError, setPasswdError] = useState('');
  const [passwdLoading, setPasswdLoading] = useState(false);

  const activeModule = getModuleById(activeModuleId);
  const viewToModuleMap: Record<string, string> = {
    dashboard: 'dashboard',
    tasks: 'task',
    assets: 'site',
    asset_monitor: 'scheduler',
    groups: 'asset_scope',
    monitoring: 'system_monitor',
    policies: 'policy',
    fingerprints: 'fingerprint',
    pocs: 'poc',
    schedules: 'task_schedule',
    github_mgmt: 'github_task',
    github_monitor: 'github_scheduler',
    api_mgmt: 'api_console',
    config_mgmt: 'config_console',
    dingtalk: 'dingtalk_api',
  };
  const moduleToViewMap = useMemo(() => {
    const reversed: Record<string, string> = {};
    Object.entries(viewToModuleMap).forEach(([view, moduleId]) => {
      reversed[moduleId] = view;
    });
    reversed.asset_site = 'groups';
    reversed.asset_domain = 'groups';
    reversed.asset_ip = 'groups';
    reversed.asset_wih = 'groups';
    reversed.site = 'assets';
    reversed.domain = 'assets';
    reversed.ip = 'assets';
    reversed.cert = 'assets';
    reversed.service = 'assets';
    reversed.fileleak = 'assets';
    reversed.url = 'assets';
    reversed.vuln = 'assets';
    reversed.cip = 'assets';
    reversed.npoc_service = 'assets';
    reversed.nuclei_result = 'assets';
    reversed.stat_finger = 'assets';
    reversed.wih = 'assets';
    reversed.github_result = 'github_mgmt';
    reversed.github_monitor_result = 'github_monitor';
    return reversed;
  }, []);
  const openModule = useCallback((moduleId: string, nextFilters?: JsonValue) => {
    setActiveModuleId(moduleId);
    setModuleExternalFilters((prev) => {
      const next = { ...prev };
      if (nextFilters && Object.keys(nextFilters).length > 0) {
        next[moduleId] = deepClone(nextFilters);
      } else {
        delete next[moduleId];
      }
      return next;
    });
  }, []);
  const activeExternalFilters = useMemo(
    () => moduleExternalFilters[activeModuleId] || {},
    [moduleExternalFilters, activeModuleId]
  );
  const clearActiveExternalFilters = useCallback(() => {
    setModuleExternalFilters((prev) => {
      if (!prev[activeModuleId]) return prev;
      const next = { ...prev };
      delete next[activeModuleId];
      return next;
    });
  }, [activeModuleId]);
  const activeViewId = useMemo(() => {
    const fallbackView = moduleToViewMap[activeModuleId] || activeModuleId;
    const isTaskDetailModule = TASK_DETAIL_TABS.some((tab) => tab.id === activeModuleId);
    if (!isTaskDetailModule) return fallbackView;

    const filters = moduleExternalFilters[activeModuleId] || {};
    const taskId = String(filters.task_id || '').trim();
    if (taskId) return 'tasks';
    return fallbackView;
  }, [activeModuleId, moduleExternalFilters, moduleToViewMap]);
  const onSidebarViewChange = (viewId: string) => {
    const mappedModuleId = viewToModuleMap[viewId] || viewId;
    openModule(mappedModuleId);
  };

  const doLogin = async (name: string, pass: string) => {
    setLoginLoading(true);
    setLoginError('');
    try {
      const result = await requestApi('', '/user/login', {
        method: 'POST',
        body: {
          username: name,
          password: pass,
        },
      });

      const newToken = result?.data?.token;
      const userName = result?.data?.username || name;
      if (!newToken) {
        throw new Error('登录返回缺少 token');
      }

      localStorage.setItem(TOKEN_KEY, newToken);
      localStorage.setItem(USERNAME_KEY, userName);
      setToken(newToken);
      setUsername(userName);
      openModule('dashboard');
    } catch (err: any) {
      setLoginError(err?.message || '登录失败');
    } finally {
      setLoginLoading(false);
    }
  };

  const doLogout = async () => {
    try {
      await requestApi(token, '/user/logout', { method: 'GET' });
    } catch {
      // ignore logout error
    }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(ACTIVE_MODULE_KEY);
    setToken('');
    setModuleExternalFilters({});
    setActiveModuleId('dashboard');
  };

  const changePassword = async () => {
    setPasswdLoading(true);
    setPasswdError('');
    try {
      const result = await requestApi(token, '/user/change_pass', {
        method: 'POST',
        body: passwdForm,
      });

      if (typeof result?.code === 'number' && result.code !== 200) {
        throw new Error(result?.message || '修改密码失败');
      }

      setPasswdDialogOpen(false);
      setPasswdForm({ old_password: '', new_password: '', check_password: '' });
      await doLogout();
    } catch (err: any) {
      setPasswdError(err?.message || '修改密码失败');
    } finally {
      setPasswdLoading(false);
    }
  };

  const openQuickCreateTask = () => {
    // 全局入口复用任务模块的“新建任务”动作模板
    const taskModule = getModuleById('task');
    const createTaskAction = taskModule.actions?.find((action) => action.id === 'create_task');
    if (!createTaskAction) {
      setGlobalNotice('任务模块未配置创建动作，已跳转任务管理');
      openModule('task');
      return;
    }

    setGlobalAction(createTaskAction);
    setGlobalActionPayload(deepClone(createTaskAction.payloadTemplate || {}));
  };

  const executeGlobalAction = async (action: ModuleAction, payload: JsonValue, file?: File | null) => {
    // 与列表动作保持一致的请求封装，避免重复实现各类动作参数处理
    const resolvedPath = applyPathTemplate(action.path, payload);
    if (/\{\w+\}/.test(resolvedPath)) {
      throw new Error('存在未填写的路径参数，请补全后再执行');
    }

    let body: JsonValue | FormData | undefined;
    let query: JsonValue | undefined;
    if (action.method === 'GET') {
      if (action.sendPayloadAsQuery) query = payload;
    } else if (action.fileFieldName) {
      if (!file) throw new Error('请先选择文件');
      const formData = new FormData();
      formData.append(action.fileFieldName, file);
      Object.entries(payload || {}).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') return;
        formData.append(key, typeof value === 'string' ? value : JSON.stringify(value));
      });
      body = formData;
    } else {
      body = payload;
    }

    const result = await requestApi(token, resolvedPath, {
      method: action.method,
      body,
      query,
      download: !!action.download,
    });

    setGlobalNotice(result?.message ? `执行成功: ${result.message}` : '操作执行成功');
    if (action.id === 'create_task') {
      openModule('task');
    }
  };

  useEffect(() => {
    if (!globalNotice) return;
    const timer = window.setTimeout(() => setGlobalNotice(''), 3200);
    return () => window.clearTimeout(timer);
  }, [globalNotice]);

  useEffect(() => {
    if (!token) return;
    localStorage.setItem(ACTIVE_MODULE_KEY, activeModuleId);
  }, [token, activeModuleId]);

  useEffect(() => {
    if (!token) return;

    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;

      if (globalAction) {
        event.preventDefault();
        setGlobalAction(null);
        return;
      }

      if (passwdDialogOpen) {
        event.preventDefault();
        setPasswdDialogOpen(false);
        setPasswdError('');
        return;
      }
    };

    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [token, globalAction, passwdDialogOpen]);

  if (!token) {
    return <LoginView onLogin={doLogin} loading={loginLoading} error={loginError} />;
  }

  return (
    <div className="h-screen flex bg-brand-bg text-white overflow-hidden">
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-[20%] left-[10%] w-[35%] h-[35%] bg-brand-accent/10 rounded-full blur-[120px]" />
        <div className="absolute top-[20%] -right-[10%] w-[30%] h-[30%] bg-brand-secondary/10 rounded-full blur-[120px]" />
        <div className="absolute -bottom-[20%] left-[30%] w-[40%] h-[40%] bg-brand-warning/10 rounded-full blur-[120px]" />
      </div>

      <Sidebar activeView={activeViewId} onViewChange={onSidebarViewChange} onNewScan={openQuickCreateTask} />

      <main className="relative z-10 flex-1 overflow-y-auto custom-scrollbar">
        <div className="sticky top-0 z-20 px-6 py-4 backdrop-blur-xl bg-brand-bg/45 border-b border-brand-border/60 flex items-center justify-between gap-4">
          <div className="text-xs text-brand-text-muted min-h-[20px]">{globalNotice || ' '}</div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-brand-text-muted px-3 py-1.5 border border-brand-border rounded-lg">{username}</span>
            <button
              onClick={() => setPasswdDialogOpen(true)}
              className="p-2.5 rounded-xl border border-brand-border hover:bg-brand-bg/60"
              title="修改密码"
            >
              <Lock className="w-4 h-4" />
            </button>
            <button
              onClick={() => void doLogout()}
              className="p-2.5 rounded-xl border border-brand-border hover:bg-brand-bg/60"
              title="退出"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        {activeModule.id === 'dashboard' ? (
          <DashboardView token={token} onOpenModule={openModule} onQuickCreateTask={openQuickCreateTask} />
        ) : null}
        {activeModule.id === 'system_monitor' ? <SystemMonitorView token={token} /> : null}
        {activeModule.id === 'api_console' ? <ApiConsoleView token={token} /> : null}
        {activeModule.id === 'config_console' ? <ConfigConsoleView token={token} /> : null}
        {activeModule.id === 'dingtalk_api' ? <DingtalkIntegrationView token={token} /> : null}
        {activeModule.id !== 'dashboard' &&
        activeModule.id !== 'system_monitor' &&
        activeModule.id !== 'api_console' &&
        activeModule.id !== 'config_console' &&
        activeModule.id !== 'dingtalk_api' ? (
          <TableModuleView
            module={activeModule}
            token={token}
            onOpenModule={openModule}
            externalFilters={activeExternalFilters}
            onClearExternalFilters={clearActiveExternalFilters}
          />
        ) : null}
      </main>

      {globalAction ? (
        <ActionDialog
          token={token}
          action={globalAction}
          initialPayload={globalActionPayload}
          onClose={() => setGlobalAction(null)}
          onSubmit={async (payload, file) => {
            await executeGlobalAction(globalAction, payload, file);
          }}
        />
      ) : null}

      {passwdDialogOpen ? (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-brand-card border border-brand-border rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-brand-border flex items-center justify-between">
              <h4 className="font-black">修改密码</h4>
              <button onClick={() => setPasswdDialogOpen(false)} className="p-2 hover:bg-brand-bg/60 rounded-xl">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-3">
              <input
                type="password"
                placeholder="旧密码"
                value={passwdForm.old_password}
                onChange={(event) => setPasswdForm((prev) => ({ ...prev, old_password: event.target.value }))}
                className="w-full bg-brand-bg border border-brand-border rounded-xl px-3 py-2.5 text-sm"
              />
              <input
                type="password"
                placeholder="新密码"
                value={passwdForm.new_password}
                onChange={(event) => setPasswdForm((prev) => ({ ...prev, new_password: event.target.value }))}
                className="w-full bg-brand-bg border border-brand-border rounded-xl px-3 py-2.5 text-sm"
              />
              <input
                type="password"
                placeholder="确认新密码"
                value={passwdForm.check_password}
                onChange={(event) => setPasswdForm((prev) => ({ ...prev, check_password: event.target.value }))}
                className="w-full bg-brand-bg border border-brand-border rounded-xl px-3 py-2.5 text-sm"
              />

              {passwdError ? <div className="text-xs text-brand-danger">{passwdError}</div> : null}

              <button
                onClick={() => void changePassword()}
                disabled={passwdLoading}
                className="w-full bg-brand-accent py-3 rounded-xl font-black text-sm uppercase tracking-wider"
              >
                {passwdLoading ? '提交中...' : '提交并重新登录'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <MainShell />
    </ThemeProvider>
  );
}
