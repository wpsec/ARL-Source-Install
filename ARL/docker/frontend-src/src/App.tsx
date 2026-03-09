import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Database,
  Download,
  FileCode,
  FlaskConical,
  GitBranch,
  Globe,
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
  inputType?: 'text' | 'number';
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
    description: '实时总览任务、资产、漏洞与系统状态',
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
    description: '任务下发、停止、重启、删除、导出',
    group: '核心功能',
    icon: Activity,
    listPath: '/task/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    exportPath: '/export/{task_id}',
    actions: [
      {
        id: 'create_task',
        label: '新建任务',
        method: 'POST',
        path: '/task/',
        payloadTemplate: {
          name: '新扫描任务',
          target: 'example.com',
          domain_brute: true,
          domain_brute_type: 'test',
          port_scan: true,
          port_scan_type: 'test',
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
        label: 'FOFA下发',
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
        label: '停止所选',
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
        label: '删除所选',
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
        label: '批量导出站点',
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
        label: '批量导出域名',
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
        label: '批量导出IP',
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
        label: '批量导出URL',
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
        id: 'task_batch_export_port',
        label: '批量导出IP端口',
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
        label: '批量导出C段',
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
        label: '批量合并报告',
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
    actions: [
      {
        id: 'task_schedule_add',
        label: '新增计划任务',
        method: 'POST',
        path: '/task_schedule/',
        payloadTemplate: {
          name: '计划任务',
          target: 'example.com',
          schedule_type: 'future_scan',
          policy_id: '',
          cron: '0 2 * * *',
          start_date: '2026-12-31 10:00:00',
          task_tag: 'task',
          notify_enable: true,
          notify_kb_enable: false,
          notify_channel: 'dingding',
          notify_on: 'finished',
        },
      },
      {
        id: 'task_schedule_stop',
        label: '停止所选',
        method: 'POST',
        path: '/task_schedule/stop/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'task_schedule_recover',
        label: '恢复所选',
        method: 'POST',
        path: '/task_schedule/recover/',
        selectedField: '_id',
        selectionMode: 'multiple',
        payloadTemplate: { _id: [] },
      },
      {
        id: 'task_schedule_delete',
        label: '删除所选',
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
    columns: ['name', 'domain', 'scope_id', 'interval', 'status'],
    columnLabels: {
      name: '名称',
      domain: '域名',
      scope_id: '资产范围ID',
      interval: '间隔(秒)',
      status: '状态',
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
              domain_brute_type: 'test',
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
    columns: ['name', 'scope', '_id'],
    columnLabels: {
      name: '资产分组名称',
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
          black_scope: '',
          scope_type: 'domain',
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
        id: 'asset_domain_add',
        label: '添加域名',
        method: 'POST',
        path: '/asset_domain/',
        payloadTemplate: {
          domain: 'www.example.com',
          scope_id: '',
          policy_id: '',
        },
      },
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
        id: 'asset_site_add_tag',
        label: '添加标签',
        method: 'POST',
        path: '/asset_site/add_tag/',
        payloadTemplate: {
          _id: '',
          tag: '重点',
        },
      },
      {
        id: 'asset_site_delete_tag',
        label: '删除标签',
        method: 'POST',
        path: '/asset_site/delete_tag/',
        payloadTemplate: {
          _id: '',
          tag: '重点',
        },
      },
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
          size: 10,
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
        id: 'asset_ip_export_only_ip',
        label: '导出IP列表',
        method: 'GET',
        path: '/asset_ip/export_ip/',
        download: true,
      },
      {
        id: 'asset_ip_export_domain',
        label: '导出关联域名',
        method: 'GET',
        path: '/asset_ip/export_domain/',
        download: true,
      },
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
    label: '站点信息',
    description: '任务扫描站点数据',
    group: '资产数据',
    icon: Globe,
    listPath: '/site/',
    rowIdKey: '_id',
    quickFilterKey: 'site',
    exportPath: '/site/export/',
    actions: [
      {
        id: 'site_add_tag',
        label: '添加标签',
        method: 'POST',
        path: '/site/add_tag/',
        payloadTemplate: {
          _id: '',
          tag: '关注',
        },
      },
      {
        id: 'site_del_tag',
        label: '删除标签',
        method: 'POST',
        path: '/site/delete_tag/',
        payloadTemplate: {
          _id: '',
          tag: '关注',
        },
      },
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
          size: 10,
        },
      },
    ],
  },
  {
    id: 'domain',
    label: '域名信息',
    description: '任务扫描域名数据',
    group: '资产数据',
    icon: Globe,
    listPath: '/domain/',
    rowIdKey: '_id',
    quickFilterKey: 'domain',
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
    label: 'IP信息',
    description: '任务扫描IP和端口数据',
    group: '资产数据',
    icon: Network,
    listPath: '/ip/',
    rowIdKey: '_id',
    quickFilterKey: 'ip',
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
    quickFilterKey: 'url',
    exportPath: '/url/export/',
  },
  {
    id: 'cert',
    label: '证书信息',
    description: 'TLS证书资产',
    group: '资产数据',
    icon: Shield,
    listPath: '/cert/',
    rowIdKey: '_id',
    quickFilterKey: 'ip',
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
    label: '服务识别',
    description: '端口服务识别结果',
    group: '资产数据',
    icon: Server,
    listPath: '/service/',
    rowIdKey: '_id',
    quickFilterKey: 'service_name',
  },
  {
    id: 'npoc_service',
    label: 'NPoC服务',
    description: 'Python实现服务识别结果',
    group: '资产数据',
    icon: Terminal,
    listPath: '/npoc_service/',
    rowIdKey: '_id',
    quickFilterKey: 'host',
  },
  {
    id: 'cip',
    label: 'C段统计',
    description: 'C段分布统计',
    group: '资产数据',
    icon: Database,
    listPath: '/cip/',
    rowIdKey: '_id',
    quickFilterKey: 'cidr_ip',
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
    quickFilterKey: 'name',
  },
  {
    id: 'vuln',
    label: '漏洞信息',
    description: '漏洞结果查询和处置',
    group: '漏洞与规则',
    icon: AlertTriangle,
    listPath: '/vuln/',
    rowIdKey: '_id',
    quickFilterKey: 'vul_name',
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
    label: 'Nuclei结果',
    description: 'Nuclei 模板扫描结果',
    group: '漏洞与规则',
    icon: FlaskConical,
    listPath: '/nuclei_result/',
    rowIdKey: '_id',
    quickFilterKey: 'vuln_name',
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
    group: '漏洞与规则',
    icon: ShieldAlert,
    listPath: '/fileleak/',
    rowIdKey: '_id',
    quickFilterKey: 'url',
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
  },
  {
    id: 'wih',
    label: '任务WIH',
    description: '任务中提取的JS信息',
    group: '漏洞与规则',
    icon: FileCode,
    listPath: '/wih/',
    rowIdKey: '_id',
    quickFilterKey: 'content',
    exportPath: '/wih/export/',
  },
  {
    id: 'poc',
    label: 'PoC管理',
    description: 'PoC / brute 插件管理',
    group: '漏洞与规则',
    icon: Shield,
    listPath: '/poc/',
    rowIdKey: '_id',
    quickFilterKey: 'plugin_name',
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
    group: '漏洞与规则',
    icon: FileCode,
    listPath: '/fingerprint/',
    rowIdKey: '_id',
    quickFilterKey: 'name',
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
    actions: [
      {
        id: 'github_scheduler_add',
        label: '新增监控任务',
        method: 'POST',
        path: '/github_scheduler/',
        payloadTemplate: {
          name: 'GitHub监控',
          keyword: 'sk_live_',
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
    description: '图形化管理系统配置并同步到 config-docker.yaml',
    group: '系统集成',
    icon: Settings,
  },
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

function extractErrorMessage(data: any): string {
  if (!data) return '请求失败';
  if (typeof data === 'string') return data;
  if (Number(data.code) === 401) return '认证失败，请检查用户名密码或重新登录';
  if (typeof data.message === 'string' && data.message) return data.message;
  if (typeof data.error === 'string' && data.error) return data.error;
  if (data.data && typeof data.data.error === 'string') return data.data.error;
  if (typeof data.detail === 'string') return data.detail;
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
      throw new Error(fallbackText || `下载失败: HTTP ${response.status}`);
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
      throw new Error(`HTTP ${response.status}: ${data.raw.slice(0, 300)}`);
    }
    throw new Error(`HTTP ${response.status}: ${extractErrorMessage(data)}`);
  }

  if (typeof data?.code === 'number' && data.code !== 200) {
    throw new Error(extractErrorMessage(data));
  }

  if (typeof data?.raw === 'string' && data.raw) {
    throw new Error(`接口返回非JSON: ${data.raw.slice(0, 300)}`);
  }

  return data;
}

function truncateText(value: string, max = 120): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}...`;
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

function formatModuleCellValue(moduleId: string, column: string, row: any): string {
  const value = getValueByPath(row, column);

  if (moduleId === 'asset_site' && column === 'finger' && Array.isArray(value)) {
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
  port_scan: '端口扫描',
  port_scan_type: '端口扫描类型',
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

      <div className="relative z-10 w-full max-w-md bg-brand-card/50 border border-brand-border backdrop-blur-xl rounded-[2rem] p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-12 h-12 rounded-2xl bg-brand-accent flex items-center justify-center shadow-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-tight">ARL 管理台</h1>
            <p className="text-xs text-brand-text-muted font-semibold uppercase tracking-widest">UI 重构版</p>
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

  return <span className={`text-xs px-3 py-1 rounded-full border font-semibold ${className}`}>{text}</span>;
}

function DashboardView({
  token,
  onOpenModule,
  onQuickCreateTask,
}: {
  token: string;
  onOpenModule: (moduleId: string) => void;
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

  const loadFallback = useCallback(async () => {
    const targets = [
      { key: 'task', path: '/task/' },
      { key: 'scheduler', path: '/scheduler/' },
      { key: 'asset_scope', path: '/asset_scope/' },
      { key: 'asset_site', path: '/asset_site/' },
      { key: 'vuln', path: '/vuln/' },
      { key: 'github_task', path: '/github_task/' },
    ] as const;

    const [responses, consoleInfo, recentTaskResponse] = await Promise.all([
      Promise.all(targets.map((target) => requestApi(token, target.path, { method: 'GET', query: { page: 1, size: 1 } }))),
      requestApi(token, '/console/info', { method: 'GET' }),
      requestApi(token, '/task/', { method: 'GET', query: { page: 1, size: 6, order: '-_id' } }),
    ]);

    const nextStats: any = {};
    responses.forEach((response, index) => {
      const normalized = normalizeListData(response);
      nextStats[targets[index].key] = normalized.total;
    });

    setStats((prev) => ({
      ...prev,
      task: Number(nextStats.task || 0),
      scheduler: Number(nextStats.scheduler || 0),
      asset_scope: Number(nextStats.asset_scope || 0),
      asset_site: Number(nextStats.asset_site || 0),
      vuln: Number(nextStats.vuln || 0),
      github_task: Number(nextStats.github_task || 0),
    }));
    setDeviceInfo(consoleInfo?.data?.device_info || {});
    setRecentTasks(normalizeListData(recentTaskResponse).items.slice(0, 6));
    setRecentLogs((prev) => (prev.length > 0 ? prev : [{ level: 'INFO', source: 'SYSTEM', msg: '当前为兼容模式，日志接口不可用', time: '' }]));
    setLastUpdatedAt(new Date().toLocaleString('zh-CN', { hour12: false }));
  }, [token]);

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
      setStats({
        task: Number(nextStats.task_total || 0),
        scheduler: Number(nextStats.scheduler_total || 0),
        asset_scope: Number(nextStats.asset_scope_total || 0),
        asset_site: Number(nextStats.asset_site_total || 0),
        vuln: Number(nextStats.vuln_total || 0),
        github_task: Number(nextStats.github_task_total || 0),
        running_task: Number(nextStats.running_tasks || 0),
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
  }, [token, loadFallback, isLogPaused]);

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
    { title: '高危漏洞', value: highRisk, change: `总计 ${stats.vuln}`, isUp: highRisk === 0, icon: AlertTriangle, color: 'text-brand-danger' },
    { title: '今日新增', value: stats.new_assets_today, change: `分组 ${stats.asset_scope}`, isUp: true, icon: Shield, color: 'text-brand-warning' },
  ];
  const trendData = assetTrend.length > 0 ? assetTrend : [{ name: '周一', assets: stats.asset_site, vulns: stats.vuln }];
  const riskData = riskDistribution.length > 0 ? riskDistribution : [{ name: '高危', value: highRisk, color: '#ef4444' }];
  const netData = networkTrend.length > 0 ? networkTrend : [{ time: '13:40', in: 120, out: 80 }];
  const logsData = recentLogs.length > 0 ? recentLogs : [{ level: 'INFO', source: 'SYSTEM', msg: '暂无日志数据', time: '' }];
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
          <h3 className="text-xl font-black tracking-tight mb-8">风险等级分布</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Bar dataKey="value" radius={[0, 8, 8, 0]} barSize={32}>
                  {riskData.map((entry, index) => (
                    <Cell key={`risk-${index}`} fill={entry?.color || '#64748b'} />
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
              <h3 className="text-xl font-black tracking-tight">实时日志</h3>
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
              <div className="mb-2 text-brand-warning border border-brand-warning/30 bg-brand-warning/10 rounded-lg px-2 py-1">日志已暂停自动刷新</div>
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
                    return (
                      <tr key={String(task?._id || task?.task_id || task?.id || Math.random())} className="border-b border-brand-border/60 last:border-b-0">
                        <td className="py-3 pr-4 font-semibold">{normalizeValue(task?.name)}</td>
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
  action,
  initialPayload,
  onClose,
  onSubmit,
}: {
  action: ModuleAction;
  initialPayload: JsonValue;
  onClose: () => void;
  onSubmit: (payload: JsonValue, file?: File | null) => Promise<void>;
}) {
  const [formPayload, setFormPayload] = useState<JsonValue>(deepClone(initialPayload));
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [file, setFile] = useState<File | null>(null);

  const editable = action.allowPayloadEdit !== false;
  const isTaskCreate = action.id === 'create_task';
  const fields = useMemo(() => flattenPayloadFields(formPayload), [formPayload]);
  const taskFeatureSections = useMemo(() => {
    if (!isTaskCreate) return [];
    const isBooleanField = (key: string) => typeof formPayload?.[key] === 'boolean';
    const sections = [
      {
        title: '域名探测',
        keys: ['domain_brute', 'alt_dns', 'dns_query_plugin', 'arl_search'],
      },
      {
        title: '网络探测',
        keys: ['port_scan', 'service_detection', 'os_detection', 'ssl_cert', 'skip_scan_cdn_ip'],
      },
      {
        title: 'Web与漏洞',
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
  const taskDomainBruteType = String(formPayload?.domain_brute_type ?? 'test');
  const taskPortScanType = String(formPayload?.port_scan_type ?? 'test');

  useEffect(() => {
    const nextPayload = deepClone(initialPayload);
    setFormPayload(nextPayload);
    setError('');
  }, [initialPayload]);

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
      <div className={`w-full ${isTaskCreate ? 'max-w-5xl' : 'max-w-3xl'} bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden`}>
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
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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
                      value={taskDomainBruteType}
                      disabled={!editable}
                      onChange={(event) => setFormPayload((prev) => updatePayloadValue(prev, 'domain_brute_type', event.target.value))}
                      className={UNIFIED_SELECT_CLASS}
                    >
                      <option value="test">test（小字典）</option>
                      <option value="big">big（大字典）</option>
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
                </div>
              </div>

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
                    </select>
                    <ChevronDown className="w-4 h-4 text-brand-text-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                  </div>
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
          ) : (
            <div className="space-y-3 max-h-[52vh] overflow-y-auto custom-scrollbar pr-1">
              {fields.map((field) => {
                const value = field.value;
                const disabled = !editable;
                const isBoolean = typeof value === 'boolean';
                const isNumber = typeof value === 'number';
                const isComplex = Array.isArray(value) || (value && typeof value === 'object');

                return (
                  <div key={field.path} className="space-y-1">
                    <label className="text-xs font-bold text-brand-text-muted">
                      {humanizeField(field.path)}
                      {!isTaskCreate ? <span className="ml-2 text-[10px] font-mono opacity-70">{field.path}</span> : null}
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
                  const payload: JsonValue = deepClone(!editable ? initialPayload : formPayload);
                  if (isTaskCreate && editable) {
                    const normalizedName = String(payload.name || '').trim();
                    const normalizedTargets = String(payload.target || '')
                      .replace(/,/g, '\n')
                      .split(/\r?\n/)
                      .map((item) => item.trim())
                      .filter((item) => item);

                    if (!normalizedName) {
                      throw new Error('请填写任务名称');
                    }
                    if (normalizedTargets.length === 0) {
                      throw new Error('请填写目标，支持一行一个');
                    }

                    payload.name = normalizedName;
                    payload.target = normalizedTargets.join('\n');
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
              {loading ? '执行中...' : '执行'}
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
}: {
  module: ModuleConfig;
  token: string;
  onOpenModule: (moduleId: string) => void;
}) {
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [quickFilter, setQuickFilter] = useState('');
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

  const hasList = Boolean(module.listPath);
  const hasAdvancedSearch = Array.isArray(module.searchFields) && module.searchFields.length > 0;

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
    setRiskDialogOpen(false);
    setRiskDialogError('');
    setRiskDialogLoading(false);
    setRiskDialogSubmitting(false);
  }, [module.id]);

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
      return filters;
    }
    if (module.quickFilterKey && quickFilter.trim()) {
      filters[module.quickFilterKey] = quickFilter.trim();
    }
    return filters;
  }, [hasAdvancedSearch, module.quickFilterKey, module.searchFields, quickFilter, searchForm]);

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

      if (module.defaultOrder && !('order' in query)) {
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
  }, [buildFilters, module.defaultOrder, module.listPath, page, size, token]);

  useEffect(() => {
    void loadRows();
  }, [loadRows]);

  const totalPages = Math.max(1, Math.ceil(total / size));

  const columns = useMemo(() => {
    if (module.columns && module.columns.length > 0) return module.columns;
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
  }, [module.columns, module.rowIdKey, rows]);

  const rowIdKey = module.rowIdKey || '_id';
  const showIndexColumn = Boolean(module.showIndex);
  const getColumnLabel = (column: string) => module.columnLabels?.[column] || humanizeField(column);

  const moduleActions = module.actions || [];
  const visibleActions = useMemo(() => {
    if (module.id !== 'asset_site') return moduleActions;
    return moduleActions.filter((action) => !['asset_site_save_result_set'].includes(action.id));
  }, [module.id, moduleActions]);

  const selectAllChecked = rows.length > 0 && selectedIds.length === rows.length;

  const openActionDialog = (action: ModuleAction) => {
    const basePayload = deepClone(action.payloadTemplate || {});

    if (action.selectedField) {
      if (action.selectionMode === 'single') {
        basePayload[action.selectedField] = selectedIds[0] || '';
      } else if (action.selectionMode === 'multiple') {
        basePayload[action.selectedField] = selectedIds;
      }
    }

    setDialogPayload(basePayload);
    setDialogAction(action);
  };

  const runAction = async (action: ModuleAction, payload: JsonValue, file?: File | null) => {
    setError('');
    setSuccess('');

    const selectionMode = action.selectionMode || 'none';
    if (selectionMode === 'single' && selectedIds.length !== 1) {
      throw new Error('该操作需要且仅需要选择一条记录');
    }
    if (selectionMode === 'multiple' && selectedIds.length === 0) {
      throw new Error('请先选择至少一条记录');
    }

    if (action.selectedField) {
      if (selectionMode === 'single') {
        payload[action.selectedField] = selectedIds[0];
      }
      if (selectionMode === 'multiple') {
        payload[action.selectedField] = selectedIds;
      }
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

  const deleteAssetScopeRow = async (scopeId: string) => {
    if (module.id !== 'asset_scope') return;
    if (!scopeId) return;
    if (!window.confirm('确认删除该资产分组吗？')) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/asset_scope/delete/', {
        method: 'POST',
        body: {
          scope_id: [scopeId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows();
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const selectionStatus =
    selectedIds.length > 0 ? `${selectedIds.length} 条已选择` : hasList ? '未选择记录' : '动作模式';
  const showAssetScopeRowOperate = module.id === 'asset_scope';

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

      {['asset_site', 'asset_domain', 'asset_ip'].includes(module.id) ? (
        <div className="flex items-center gap-2">
          {[
            { id: 'asset_site', label: '站点' },
            { id: 'asset_domain', label: '子域名' },
            { id: 'asset_ip', label: 'IP' },
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

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
        {hasAdvancedSearch ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {(module.searchFields || []).map((field) => (
                <div key={field.key} className="space-y-1">
                  <label className="text-xs font-bold text-brand-text-muted">{field.label}：</label>
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
                </div>
              ))}
            </div>

            <div className="flex flex-wrap gap-2">
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
              <button
                onClick={clearSearchFilters}
                className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                disabled={loading || !hasList}
              >
                <RefreshCw className="w-4 h-4" />
                {module.id === 'asset_site' ? '清除' : '重置'}
              </button>
              {module.exportPath ? (
                <button
                  onClick={() => void runExport()}
                  className="px-4 py-2.5 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  {module.id === 'asset_site' ? '导出站点' : '导出'}
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
              const disabled =
                (needSingle && selectedIds.length !== 1) ||
                (needMultiple && selectedIds.length === 0);

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
          </div>
        ) : null}
      </div>

      {hasList ? (
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl overflow-hidden">
          <div className="overflow-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead className="bg-brand-bg/40 border-b border-brand-border">
                <tr>
                  <th className="px-4 py-3 w-12">
                    <input
                      type="checkbox"
                      checked={selectAllChecked}
                      className="h-5 w-5 cursor-pointer rounded-md border border-brand-border bg-brand-bg"
                      onChange={(event) => {
                        if (event.target.checked) {
                          const ids = rows
                            .map((row) => String(row?.[rowIdKey] ?? ''))
                            .filter((value) => value);
                          setSelectedIds(ids);
                        } else {
                          setSelectedIds([]);
                        }
                      }}
                    />
                  </th>
                  {showIndexColumn ? (
                    <th className="px-4 py-3 text-xs uppercase tracking-wider font-black text-brand-text-muted whitespace-nowrap">序号</th>
                  ) : null}
                  {columns.map((column) => (
                    <th key={column} className="px-4 py-3 text-xs uppercase tracking-wider font-black text-brand-text-muted whitespace-nowrap">
                      {getColumnLabel(column)}
                    </th>
                  ))}
                  {showAssetScopeRowOperate ? (
                    <th className="px-4 py-3 text-xs uppercase tracking-wider font-black text-brand-text-muted whitespace-nowrap">操作</th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, rowIndex) => {
                  const id = String(row?.[rowIdKey] ?? '');
                  const checked = selectedIds.includes(id);

                  return (
                    <tr key={id || Math.random()} className="border-b border-brand-border/60 hover:bg-white/5 transition">
                      <td className="px-4 py-3">
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
                        <td className="px-4 py-3 align-top font-mono text-xs whitespace-nowrap">
                          {(page - 1) * size + rowIndex + 1}
                        </td>
                      ) : null}
                      {columns.map((column) => (
                        <td key={column} className="px-4 py-3 align-top font-mono text-xs whitespace-nowrap">
                          {formatModuleCellValue(module.id, column, row)}
                        </td>
                      ))}
                      {showAssetScopeRowOperate ? (
                        <td className="px-4 py-3 align-top whitespace-nowrap">
                          <button
                            onClick={() => void deleteAssetScopeRow(id)}
                            className="px-3 py-1.5 rounded-lg border border-brand-border text-xs font-semibold hover:bg-brand-bg/70 transition"
                          >
                            删除
                          </button>
                        </td>
                      ) : null}
                    </tr>
                  );
                })}
                {rows.length === 0 && !loading ? (
                  <tr>
                    <td
                      colSpan={Math.max(columns.length + 1 + (showIndexColumn ? 1 : 0) + (showAssetScopeRowOperate ? 1 : 0), 2)}
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
    </div>
  );
}

function ApiConsoleView({ token }: { token: string }) {
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
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [dictOptions, setDictOptions] = useState<DomainDictOption[]>([]);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const uploadInputRef = useRef<HTMLInputElement | null>(null);

  const [domainDict, setDomainDict] = useState('');
  const [domainBruteConcurrent, setDomainBruteConcurrent] = useState(300);
  const [altDnsConcurrent, setAltDnsConcurrent] = useState(1500);
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
      const nextOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];

      setDomainDict(String(scanConfig.domain_dict || ''));
      setDomainBruteConcurrent(Number(scanConfig.domain_brute_concurrent || 300));
      setAltDnsConcurrent(Number(scanConfig.alt_dns_concurrent || 1500));
      setBlackIpsText(Array.isArray(scanConfig.black_ips) ? scanConfig.black_ips.join('\n') : '');
      setDnsResolversText(Array.isArray(scanConfig.dns_resolvers) ? scanConfig.dns_resolvers.join('\n') : '');

      setDictOptions(nextOptions);
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
    const normalizedDict = domainDict.trim();
    if (!normalizedDict) {
      setError('请先选择域名爆破字典');
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
            domain_dict: normalizedDict,
            domain_brute_concurrent: Math.floor(domainBruteConcurrent),
            alt_dns_concurrent: Math.floor(altDnsConcurrent),
            black_ips: blackIps,
            dns_resolvers: splitTextList(dnsResolversText),
          },
        },
      });

      const data = result?.data || {};
      const savedConfig = data?.scan_config || {};
      const nextOptions = Array.isArray(data?.available_domain_dicts) ? data.available_domain_dicts : [];
      const backupPath = data?.backup_path ? `，备份: ${data.backup_path}` : '';

      setDomainDict(String(savedConfig.domain_dict || normalizedDict));
      setDomainBruteConcurrent(Number(savedConfig.domain_brute_concurrent || domainBruteConcurrent));
      setAltDnsConcurrent(Number(savedConfig.alt_dns_concurrent || altDnsConcurrent));
      setBlackIpsText(Array.isArray(savedConfig.black_ips) ? savedConfig.black_ips.join('\n') : blackIpsText);
      setDnsResolversText(Array.isArray(savedConfig.dns_resolvers) ? savedConfig.dns_resolvers.join('\n') : dnsResolversText);

      setDictOptions(nextOptions);
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
    if (!uploadFile) {
      setError('请先选择要上传的字典文件');
      return;
    }

    setUploading(true);
    setError('');
    setSuccess('');
    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
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
      setDictOptions(nextOptions);
      setUpdatedAt(String(data.saved_at || updatedAt));
      setSuccess(`字典上传成功: ${uploadFile.name}`);

      setUploadFile(null);
      if (uploadInputRef.current) {
        uploadInputRef.current.value = '';
      }
    } catch (err: any) {
      setError(err?.message || '字典上传失败');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div>
        <h2 className="text-4xl font-black tracking-tight">API 管理</h2>
        <p className="text-brand-text-muted mt-2 text-sm">扫描配置仅保留域名爆破字典、并发参数、黑名单IP与域名解析器配置。</p>
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
              disabled={saving || loading || uploading}
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
              {dictOptions.map((item) => (
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
              ref={uploadInputRef}
              type="file"
              accept=".txt"
              className="flex-1 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm"
              onChange={(event) => {
                const file = event.target.files?.[0];
                setUploadFile(file || null);
              }}
            />
            <button
              onClick={() => void uploadDomainDict()}
              className="px-4 py-2 rounded-xl border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition flex items-center justify-center gap-2 disabled:opacity-60"
              disabled={uploading || loading || saving}
            >
              <Upload className={`w-4 h-4 ${uploading ? 'animate-spin' : ''}`} />
              {uploading ? '上传中...' : '上传字典'}
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

function MainShell() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [username, setUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || 'admin');
  const [activeModuleId, setActiveModuleId] = useState(() => resolveStoredModuleId(localStorage.getItem(ACTIVE_MODULE_KEY)));
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
    assets: 'asset_site',
    groups: 'asset_scope',
    monitoring: 'system_monitor',
    policies: 'policy',
    fingerprints: 'fingerprint',
    pocs: 'poc',
    schedules: 'task_schedule',
    github_mgmt: 'github_task',
    github_monitor: 'github_scheduler',
    api_mgmt: 'api_console',
    dingtalk: 'dingtalk_api',
  };
  const moduleToViewMap = useMemo(() => {
    const reversed: Record<string, string> = {};
    Object.entries(viewToModuleMap).forEach(([view, moduleId]) => {
      reversed[moduleId] = view;
    });
    return reversed;
  }, []);
  const activeViewId = moduleToViewMap[activeModuleId] || activeModuleId;
  const onSidebarViewChange = (viewId: string) => {
    const mappedModuleId = viewToModuleMap[viewId] || viewId;
    setActiveModuleId(mappedModuleId);
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
      setActiveModuleId('dashboard');
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
      setActiveModuleId('task');
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
      setActiveModuleId('task');
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
          <DashboardView token={token} onOpenModule={setActiveModuleId} onQuickCreateTask={openQuickCreateTask} />
        ) : null}
        {activeModule.id === 'system_monitor' ? <SystemMonitorView token={token} /> : null}
        {activeModule.id === 'api_console' ? <ApiConsoleView token={token} /> : null}
        {activeModule.id !== 'dashboard' && activeModule.id !== 'system_monitor' && activeModule.id !== 'api_console' ? (
          <TableModuleView module={activeModule} token={token} onOpenModule={setActiveModuleId} />
        ) : null}
      </main>

      {globalAction ? (
        <ActionDialog
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
