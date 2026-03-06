import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  CheckCircle2,
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
} from 'lucide-react';
import { ThemeProvider, ThemeType, useTheme } from './context/ThemeContext';

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

const themes: { id: ThemeType; label: string; color: string }[] = [
  { id: 'midnight', label: '午夜科技', color: 'bg-[#6366f1]' },
  { id: 'titanium', label: '钛金黑', color: 'bg-[#3b82f6]' },
  { id: 'slate', label: '专业灰蓝', color: 'bg-[#38bdf8]' },
  { id: 'nord', label: '北欧极光', color: 'bg-[#88c0d0]' },
  { id: 'sandstone', label: '砂岩白', color: 'bg-[#44403c]' },
  { id: 'deepsea', label: '深海探测', color: 'bg-[#00b4d8]' },
  { id: 'forest', label: '森林卫士', color: 'bg-[#10b981]' },
  { id: 'crimson', label: '绯红之刃', color: 'bg-[#e11d48]' },
  { id: 'cyberpunk', label: '赛博朋克', color: 'bg-[#ff00ff]' },
  { id: 'minimalist', label: '极简白昼', color: 'bg-[#0f172a]' },
];

const modules: ModuleConfig[] = [
  {
    id: 'dashboard',
    label: '我的仪表盘',
    description: '实时总览任务、资产、漏洞与系统状态',
    group: '核心功能',
    icon: LayoutDashboard,
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
    description: '资产组周期监控、站点监控、WIH监控',
    group: '核心功能',
    icon: Monitor,
    listPath: '/scheduler/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    actions: [
      {
        id: 'scheduler_add',
        label: '新增监控任务',
        method: 'POST',
        path: '/scheduler/add/',
        payloadTemplate: {
          scope_id: '',
          domain: 'example.com',
          interval: 21600,
          name: '资产监控',
          policy_id: '',
        },
      },
      {
        id: 'scheduler_add_site_monitor',
        label: '新增站点监控',
        method: 'POST',
        path: '/scheduler/add/site_monitor/',
        payloadTemplate: {
          scope_id: '',
          interval: 21600,
          name: '站点监控',
        },
      },
      {
        id: 'scheduler_add_wih_monitor',
        label: '新增WIH监控',
        method: 'POST',
        path: '/scheduler/add/wih_monitor/',
        payloadTemplate: {
          scope_id: '',
          interval: 21600,
          name: 'WIH监控',
        },
      },
      {
        id: 'scheduler_stop',
        label: '停止所选',
        method: 'POST',
        path: '/scheduler/stop/batch',
        selectedField: 'job_id',
        selectionMode: 'multiple',
        payloadTemplate: { job_id: [] },
      },
      {
        id: 'scheduler_recover',
        label: '恢复所选',
        method: 'POST',
        path: '/scheduler/recover/batch',
        selectedField: 'job_id',
        selectionMode: 'multiple',
        payloadTemplate: { job_id: [] },
      },
      {
        id: 'scheduler_delete',
        label: '删除所选',
        method: 'POST',
        path: '/scheduler/delete/',
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
    description: '资产组和范围管理',
    group: '核心功能',
    icon: Shield,
    listPath: '/asset_scope/',
    rowIdKey: '_id',
    defaultOrder: '-_id',
    quickFilterKey: 'name',
    actions: [
      {
        id: 'asset_scope_add',
        label: '新增资产组',
        method: 'POST',
        path: '/asset_scope/',
        payloadTemplate: {
          name: '新资产组',
          scope: 'example.com',
          black_scope: '',
          scope_type: 'domain',
        },
      },
      {
        id: 'asset_scope_add_scope',
        label: '扩展范围',
        method: 'POST',
        path: '/asset_scope/add/',
        payloadTemplate: {
          scope_id: '',
          scope: 'sub.example.com',
        },
      },
      {
        id: 'asset_scope_delete',
        label: '删除所选分组',
        method: 'POST',
        path: '/asset_scope/delete/',
        selectedField: 'scope_id',
        selectionMode: 'multiple',
        payloadTemplate: { scope_id: [] },
      },
      {
        id: 'asset_scope_batch_export_ip',
        label: '批量导出资产IP',
        method: 'POST',
        path: '/batch_export/asset_ip/',
        selectedField: 'scope_id',
        selectionMode: 'multiple',
        payloadTemplate: { scope_id: [] },
        download: true,
      },
      {
        id: 'asset_scope_batch_export_domain',
        label: '批量导出资产域名',
        method: 'POST',
        path: '/batch_export/asset_domain/',
        selectedField: 'scope_id',
        selectionMode: 'multiple',
        payloadTemplate: { scope_id: [] },
        download: true,
      },
      {
        id: 'asset_scope_batch_export_site',
        label: '批量导出资产站点',
        method: 'POST',
        path: '/batch_export/asset_site/',
        selectedField: 'scope_id',
        selectionMode: 'multiple',
        payloadTemplate: { scope_id: [] },
        download: true,
      },
      {
        id: 'asset_scope_batch_export_wih',
        label: '批量导出资产WIH',
        method: 'POST',
        path: '/batch_export/asset_wih/',
        selectedField: 'scope_id',
        selectionMode: 'multiple',
        payloadTemplate: { scope_id: [] },
        download: true,
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
    exportPath: '/asset_site/export/',
    actions: [
      {
        id: 'asset_site_add',
        label: '添加站点',
        method: 'POST',
        path: '/asset_site/',
        payloadTemplate: {
          site: 'https://example.com',
          scope_id: '',
          policy_id: '',
        },
      },
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
    label: 'API控制台',
    description: '任意 API 调试，覆盖全部后端功能',
    group: '系统集成',
    icon: Terminal,
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
  if (Array.isArray(value)) return truncateText(JSON.stringify(value));
  if (typeof value === 'object') return truncateText(JSON.stringify(value));
  return truncateText(String(value));
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

function parseJsonObject(text: string): JsonValue {
  const trimmed = text.trim();
  if (!trimmed) return {};
  const parsed = JSON.parse(trimmed);
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    return parsed;
  }
  throw new Error('请输入 JSON 对象，例如 {"name":"demo"}');
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
  search_engines: '搜索引擎',
  site_spider: '站点爬虫',
  arl_search: 'ARL历史查询',
  alt_dns: 'AltDNS',
  ssl_cert: 'SSL证书收集',
  dns_query_plugin: 'DNS插件查询',
  skip_scan_cdn_ip: '跳过CDN IP扫描',
  nuclei_scan: 'Nuclei扫描',
  findvhost: '虚拟主机探测',
  web_info_hunter: 'Web信息猎取',
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

function DashboardView({ token }: { token: string }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [stats, setStats] = useState({
    task: 0,
    scheduler: 0,
    asset_scope: 0,
    asset_site: 0,
    vuln: 0,
    github_task: 0,
  });
  const [deviceInfo, setDeviceInfo] = useState<any>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const targets = [
        { key: 'task', path: '/task/' },
        { key: 'scheduler', path: '/scheduler/' },
        { key: 'asset_scope', path: '/asset_scope/' },
        { key: 'asset_site', path: '/asset_site/' },
        { key: 'vuln', path: '/vuln/' },
        { key: 'github_task', path: '/github_task/' },
      ] as const;

      const responses = await Promise.all(
        targets.map((target) => requestApi(token, target.path, { method: 'GET', query: { page: 1, size: 1 } }))
      );

      const nextStats: any = {};
      responses.forEach((response, index) => {
        const normalized = normalizeListData(response);
        nextStats[targets[index].key] = normalized.total;
      });
      setStats(nextStats);

      const consoleInfo = await requestApi(token, '/console/info', { method: 'GET' });
      setDeviceInfo(consoleInfo?.data?.device_info || {});
    } catch (err: any) {
      setError(err?.message || '加载仪表盘失败');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const cards = [
    { title: '扫描任务', value: stats.task, icon: Activity, color: 'text-brand-accent' },
    { title: '监控任务', value: stats.scheduler, icon: RefreshCw, color: 'text-brand-secondary' },
    { title: '资产分组', value: stats.asset_scope, icon: Shield, color: 'text-emerald-400' },
    { title: '资产站点', value: stats.asset_site, icon: Globe, color: 'text-brand-warning' },
    { title: '漏洞总数', value: stats.vuln, icon: AlertTriangle, color: 'text-brand-danger' },
    { title: 'GitHub任务', value: stats.github_task, icon: GitBranch, color: 'text-brand-accent' },
  ];
  // 兼容后端不同版本的字段命名
  const memoryInfo = deviceInfo?.memory || deviceInfo?.virtual_memory;
  const diskInfo = deviceInfo?.disk || deviceInfo?.disk_usage;

  return (
    <div className="p-8 space-y-8">
      <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
        <div>
          <h2 className="text-5xl font-black tracking-tight">我的仪表盘</h2>
          <p className="text-brand-text-muted font-medium mt-2">全模块 API 已接入，可直接在左侧各页执行真实操作。</p>
        </div>
        <button
          onClick={() => void load()}
          className="px-4 py-2 border border-brand-border rounded-xl text-sm font-semibold hover:bg-brand-card/60 transition flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          刷新数据
        </button>
      </div>

      {error ? (
        <div className="text-sm text-brand-danger border border-brand-danger/30 bg-brand-danger/10 rounded-xl px-4 py-3">{error}</div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
        {cards.map((card) => (
          <div key={card.title} className="bg-brand-card/40 border border-brand-border rounded-2xl p-5 backdrop-blur-lg shadow-xl shadow-black/10">
            <div className="flex items-center justify-between mb-4">
              <p className="text-xs uppercase tracking-widest font-bold text-brand-text-muted">{card.title}</p>
              <card.icon className={`w-5 h-5 ${card.color}`} />
            </div>
            <p className="text-3xl font-black tracking-tight">{card.value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-2 bg-brand-card/40 border border-brand-border rounded-2xl p-6">
          <h3 className="text-lg font-black mb-4">运行建议</h3>
          <div className="space-y-3 text-sm text-brand-text-muted leading-relaxed">
            <p>1. 先在“策略配置”页维护标准策略，再通过“任务管理 → 策略下发”统一执行。</p>
            <p>2. 定时能力分为“资产监控(scheduler)”和“计划任务(task_schedule)”两套，按场景分别使用。</p>
            <p>3. 导出报告支持单任务、批量任务、批量资产组，均已在各模块操作面板接入。</p>
            <p>4. 所有操作统一使用可视化表单，减少参数输入错误。</p>
          </div>
        </div>

        <div className="bg-brand-card/40 border border-brand-border rounded-2xl p-6">
          <h3 className="text-lg font-black mb-4">主机资源</h3>
          <div className="space-y-4 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-brand-text-muted">CPU</span>
              <span className="font-semibold">{formatCpuSummary(deviceInfo)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-brand-text-muted">内存</span>
              <span className="font-semibold">{formatUsageSummary(memoryInfo)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-brand-text-muted">磁盘</span>
              <span className="font-semibold">{formatUsageSummary(diskInfo)}</span>
            </div>
          </div>
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
  const fields = useMemo(() => flattenPayloadFields(formPayload), [formPayload]);

  useEffect(() => {
    const nextPayload = deepClone(initialPayload);
    setFormPayload(nextPayload);
    setError('');
  }, [initialPayload]);

  return (
    <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-brand-card border border-brand-border rounded-2xl shadow-2xl overflow-hidden">
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
                    <span className="ml-2 text-[10px] font-mono opacity-70">{field.path}</span>
                  </label>
                  {isBoolean ? (
                    <label className="flex items-center gap-2 rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-sm">
                      <input
                        type="checkbox"
                        checked={value}
                        disabled={disabled}
                        onChange={(event) => {
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, event.target.checked));
                        }}
                      />
                      <span>{value ? '启用' : '关闭'}</span>
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
                    <textarea
                      value={JSON.stringify(value, null, 2)}
                      disabled={disabled}
                      onChange={(event) => {
                        try {
                          const parsed = JSON.parse(event.target.value || 'null');
                          setFormPayload((prev) => updatePayloadValue(prev, field.path, parsed));
                          setError('');
                        } catch {
                          setError(`字段 ${field.path} 的 JSON 格式错误`);
                        }
                      }}
                      className="w-full min-h-[88px] rounded-xl border border-brand-border bg-brand-bg px-3 py-2 text-xs font-mono"
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

          <details>
            <summary className="cursor-pointer text-xs font-semibold text-brand-text-muted">预览 JSON</summary>
            <pre className="mt-2 bg-brand-bg border border-brand-border rounded-xl p-3 text-xs font-mono overflow-auto max-h-48">
              {JSON.stringify(formPayload, null, 2)}
            </pre>
          </details>

          {!editable ? (
            <div className="text-xs text-brand-text-muted bg-brand-bg/60 border border-brand-border rounded-lg px-3 py-2">
              当前动作使用固定参数，已禁用编辑。
            </div>
          ) : null}

          {action.id === 'create_task' ? (
            <div className="text-xs text-brand-text-muted bg-brand-accent/10 border border-brand-accent/30 rounded-lg px-3 py-2">
              建议先填写任务名称与目标，再按需勾选扫描选项。此处已是完整任务参数，不需要手写 JSON。
            </div>
          ) : null}

          <div className="text-xs text-brand-text-muted">提示：当前仅保留表单模式，减少误操作和配置成本。</div>

          {error ? (
            <div className="text-xs text-brand-danger bg-brand-danger/10 border border-brand-danger/30 rounded-lg px-3 py-2">{error}</div>
          ) : null}

          <div className="flex justify-end gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-brand-border text-sm font-semibold hover:bg-brand-bg/70 transition"
            >
              取消
            </button>
            <button
              onClick={async () => {
                try {
                  setLoading(true);
                  setError('');
                  const payload: JsonValue = !editable ? initialPayload : formPayload;
                  await onSubmit(payload, file);
                  onClose();
                } catch (err: any) {
                  setError(err?.message || '执行失败');
                } finally {
                  setLoading(false);
                }
              }}
              className="px-4 py-2 rounded-lg bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider uppercase"
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

function TableModuleView({ module, token }: { module: ModuleConfig; token: string }) {
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [quickFilter, setQuickFilter] = useState('');
  const [filterJson, setFilterJson] = useState('{}');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [dialogAction, setDialogAction] = useState<ModuleAction | null>(null);
  const [dialogPayload, setDialogPayload] = useState<JsonValue>({});

  const hasList = Boolean(module.listPath);

  const loadRows = useCallback(async () => {
    if (!module.listPath) return;
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      let filters: JsonValue = {};
      try {
        filters = parseJsonObject(filterJson);
      } catch (parseErr: any) {
        setError(parseErr?.message || '高级过滤 JSON 格式错误');
        return;
      }
      if (module.quickFilterKey && quickFilter.trim()) {
        filters[module.quickFilterKey] = quickFilter.trim();
      }

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
  }, [filterJson, module.defaultOrder, module.listPath, module.quickFilterKey, page, quickFilter, size, token]);

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

  const visibleActions = module.actions || [];

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
      let filters: JsonValue = {};
      try {
        filters = parseJsonObject(filterJson);
      } catch (parseErr: any) {
        setError(parseErr?.message || '高级过滤 JSON 格式错误');
        return;
      }
      if (module.quickFilterKey && quickFilter.trim()) {
        filters[module.quickFilterKey] = quickFilter.trim();
      }
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

  const selectionStatus =
    selectedIds.length > 0 ? `${selectedIds.length} 条已选择` : hasList ? '未选择记录' : '动作模式';

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

      <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-4 space-y-4">
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

        <details>
          <summary className="cursor-pointer text-sm font-semibold text-brand-text-muted">高级过滤 JSON</summary>
          <textarea
            value={filterJson}
            onChange={(event) => {
              setFilterJson(event.target.value);
              setPage(1);
            }}
            className="mt-3 w-full h-28 bg-brand-bg border border-brand-border rounded-xl p-3 font-mono text-xs"
            placeholder='{"status":"running","task_id":"xxx"}'
          />
        </details>

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
                  className="px-3 py-2 rounded-lg text-xs font-bold tracking-wider uppercase border border-brand-border hover:bg-brand-bg/70 disabled:opacity-40 disabled:cursor-not-allowed transition"
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
                  {columns.map((column) => (
                    <th key={column} className="px-4 py-3 text-xs uppercase tracking-wider font-black text-brand-text-muted whitespace-nowrap">
                      {column}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const id = String(row?.[rowIdKey] ?? '');
                  const checked = selectedIds.includes(id);

                  return (
                    <tr key={id || Math.random()} className="border-b border-brand-border/60 hover:bg-white/5 transition">
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={checked}
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
                      {columns.map((column) => (
                        <td key={column} className="px-4 py-3 align-top font-mono text-xs whitespace-nowrap">
                          {normalizeValue(row?.[column])}
                        </td>
                      ))}
                    </tr>
                  );
                })}
                {rows.length === 0 && !loading ? (
                  <tr>
                    <td colSpan={Math.max(columns.length + 1, 2)} className="px-4 py-10 text-center text-brand-text-muted">
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
                className="px-3 py-1.5 rounded-lg border border-brand-border text-xs disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <select
                value={size}
                onChange={(event) => {
                  setSize(Number(event.target.value));
                  setPage(1);
                }}
                className="bg-brand-bg border border-brand-border rounded-lg px-2 py-1.5 text-xs"
              >
                {[10, 20, 50, 100].map((option) => (
                  <option key={option} value={option}>
                    {option} / 页
                  </option>
                ))}
              </select>
              <button
                onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
                disabled={page >= totalPages}
                className="px-3 py-1.5 rounded-lg border border-brand-border text-xs disabled:opacity-40"
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
    </div>
  );
}

function ApiConsoleView({ token }: { token: string }) {
  const [method, setMethod] = useState<HttpMethod>('GET');
  const [path, setPath] = useState('/task/');
  const [queryText, setQueryText] = useState('{"page":1,"size":10}');
  const [bodyText, setBodyText] = useState('{}');
  const [resultText, setResultText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  return (
    <div className="p-8 space-y-6">
      <div>
        <h2 className="text-4xl font-black tracking-tight">API 控制台</h2>
        <p className="text-brand-text-muted mt-2 text-sm">用于覆盖所有后端接口。支持 GET/POST、Query、JSON Body 和实时返回。</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <select
              value={method}
              onChange={(event) => setMethod(event.target.value as HttpMethod)}
              className="col-span-1 bg-brand-bg border border-brand-border rounded-xl px-3 py-2 text-sm"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
            <input
              value={path}
              onChange={(event) => setPath(event.target.value)}
              className="col-span-2 bg-brand-bg border border-brand-border rounded-xl px-3 py-2 text-sm font-mono"
              placeholder="/task/"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-brand-text-muted">Query JSON</label>
            <textarea
              value={queryText}
              onChange={(event) => setQueryText(event.target.value)}
              className="w-full h-32 bg-brand-bg border border-brand-border rounded-xl p-3 text-xs font-mono"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-brand-text-muted">Body JSON</label>
            <textarea
              value={bodyText}
              onChange={(event) => setBodyText(event.target.value)}
              className="w-full h-44 bg-brand-bg border border-brand-border rounded-xl p-3 text-xs font-mono"
              disabled={method === 'GET'}
            />
          </div>

          <div className="flex gap-3">
            <button
              onClick={async () => {
                try {
                  setLoading(true);
                  setError('');
                  const query = parseJsonObject(queryText);
                  const body = method === 'GET' ? undefined : parseJsonObject(bodyText);
                  const result = await requestApi(token, path, {
                    method,
                    query,
                    body,
                  });
                  setResultText(JSON.stringify(result, null, 2));
                } catch (err: any) {
                  setError(err?.message || '请求失败');
                  setResultText('');
                } finally {
                  setLoading(false);
                }
              }}
              className="px-4 py-2 rounded-xl bg-brand-accent text-white font-black text-xs uppercase tracking-wider"
              disabled={loading}
            >
              {loading ? '请求中...' : '执行请求'}
            </button>
          </div>

          {error ? <div className="text-xs text-brand-danger">{error}</div> : null}
        </div>

        <div className="bg-brand-card/35 border border-brand-border rounded-2xl p-5 space-y-2">
          <label className="text-xs font-bold uppercase tracking-wider text-brand-text-muted">返回结果</label>
          <pre className="w-full h-[580px] bg-brand-bg border border-brand-border rounded-xl p-3 text-xs font-mono overflow-auto whitespace-pre-wrap break-all">
            {resultText || '// 等待执行'}
          </pre>
        </div>
      </div>
    </div>
  );
}

function MainShell() {
  const { theme, setTheme } = useTheme();
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [username, setUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || 'admin');
  const [activeModuleId, setActiveModuleId] = useState('dashboard');
  const [loginError, setLoginError] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);
  const [passwdDialogOpen, setPasswdDialogOpen] = useState(false);
  const [passwdForm, setPasswdForm] = useState({ old_password: '', new_password: '', check_password: '' });
  const [passwdError, setPasswdError] = useState('');
  const [passwdLoading, setPasswdLoading] = useState(false);

  const activeModule = getModuleById(activeModuleId);

  const groupedModules = useMemo(() => {
    const map = new Map<string, ModuleConfig[]>();
    modules.forEach((module) => {
      const list = map.get(module.group) || [];
      list.push(module);
      map.set(module.group, list);
    });
    return Array.from(map.entries());
  }, []);
  // 侧栏分组颜色映射，便于按业务域快速识别模块分区
  const groupToneMap: Record<string, string> = {
    核心功能: 'text-brand-accent',
    资产数据: 'text-brand-secondary',
    漏洞与规则: 'text-brand-warning',
    GitHub监控: 'text-emerald-400',
    系统集成: 'text-brand-text-muted',
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
    setToken('');
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

  useEffect(() => {
    if (!token) return;

    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;

      if (passwdDialogOpen) {
        event.preventDefault();
        setPasswdDialogOpen(false);
        setPasswdError('');
        return;
      }

      if (activeModuleId !== 'dashboard') {
        event.preventDefault();
        setActiveModuleId('dashboard');
      }
    };

    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [token, passwdDialogOpen, activeModuleId]);

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

      <aside className="relative z-10 w-72 border-r border-brand-border bg-brand-bg/70 backdrop-blur-xl flex flex-col overflow-y-auto custom-scrollbar">
        <div className="p-6 space-y-5 border-b border-brand-border/80">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-brand-accent flex items-center justify-center shadow-xl shadow-black/30">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight">ARL</h1>
              <p className="text-[10px] uppercase tracking-[0.28em] text-brand-accent font-black">Lighthouse UI</p>
            </div>
          </div>
          <p className="text-xs text-brand-text-muted leading-relaxed">已按新 UI 风格统一侧栏视觉，底层 API 与功能保持不变。</p>
          <button
            onClick={() => setActiveModuleId('task')}
            className="w-full bg-brand-accent text-white font-black py-3.5 px-4 rounded-2xl flex items-center justify-center gap-2 shadow-lg shadow-black/20 hover:opacity-90 transition text-sm"
          >
            <Plus className="w-4 h-4" />
            新建任务
          </button>
        </div>

        <div className="flex-1 px-3 py-4 space-y-6">
          {groupedModules.map(([groupName, groupModules]) => (
            <div key={groupName} className="space-y-2">
              <h3 className={`text-[11px] px-3 uppercase tracking-[0.15em] font-black opacity-70 ${groupToneMap[groupName] || 'text-brand-text-muted'}`}>
                {groupName}
              </h3>
              <div className="space-y-1">
                {groupModules.map((module) => (
                  <button
                    key={module.id}
                    onClick={() => setActiveModuleId(module.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold transition ${
                      activeModuleId === module.id
                        ? 'bg-brand-accent/12 text-brand-accent border border-brand-accent/30'
                        : 'text-brand-text-muted hover:text-white hover:bg-brand-card/55 border border-transparent'
                    }`}
                  >
                    <module.icon className="w-4 h-4" />
                    <span className="truncate">{module.label}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="p-4 border-t border-brand-border space-y-4">
          <div className="space-y-2">
            <p className="text-[10px] uppercase tracking-widest font-black text-brand-text-muted">主题定制</p>
            <div className="flex flex-wrap gap-2">
              {themes.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setTheme(item.id)}
                  title={item.label}
                  className={`w-6 h-6 rounded-lg border-2 ${item.color} ${
                    theme === item.id ? 'border-white scale-110' : 'border-transparent opacity-60 hover:opacity-100'
                  }`}
                />
              ))}
            </div>
          </div>

          <div className="bg-brand-card/40 border border-brand-border rounded-xl p-3 flex items-center justify-between">
            <div>
              <p className="text-sm font-bold">{username}</p>
              <p className="text-[10px] uppercase tracking-wider text-brand-text-muted">管理员会话</p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPasswdDialogOpen(true)}
                className="p-2 rounded-lg border border-brand-border hover:bg-brand-bg/60"
                title="修改密码"
              >
                <Lock className="w-4 h-4" />
              </button>
              <button
                onClick={() => void doLogout()}
                className="p-2 rounded-lg border border-brand-border hover:bg-brand-bg/60"
                title="退出"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </aside>

      <main className="relative z-10 flex-1 overflow-y-auto custom-scrollbar">
        {activeModule.id === 'dashboard' ? <DashboardView token={token} /> : null}
        {activeModule.id === 'api_console' ? <ApiConsoleView token={token} /> : null}
        {activeModule.id !== 'dashboard' && activeModule.id !== 'api_console' ? <TableModuleView module={activeModule} token={token} /> : null}
      </main>

      {passwdDialogOpen ? (
        <div className="fixed inset-0 z-50 bg-black/55 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-brand-card border border-brand-border rounded-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-brand-border flex items-center justify-between">
              <h4 className="font-black">修改密码</h4>
              <button onClick={() => setPasswdDialogOpen(false)} className="p-1.5 hover:bg-brand-bg/60 rounded-lg">
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
                className="w-full bg-brand-accent py-2.5 rounded-xl font-black text-xs uppercase tracking-wider"
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
