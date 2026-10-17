import { ChevronDown } from 'lucide-react';
import {
  TASK_REPORT_EXPORT_OPTIONS,
} from '../../config/modules';
import type {
  JsonValue,
  ModuleAction,
  TaskReportExportFormat,
} from '../../domain/types';
import { CONSOLE_SECONDARY_BUTTON_CLASS } from '../../ui/classes';

const ROW_OPERATION_GROUP_CLASS = 'inline-flex flex-nowrap items-center justify-center gap-2 min-w-max';
const ROW_OPERATION_BUTTON_CLASS = `${CONSOLE_SECONDARY_BUTTON_CLASS} text-sm font-medium shrink-0`;
const ROW_OPERATION_DISABLED_BUTTON_CLASS = `${ROW_OPERATION_BUTTON_CLASS} disabled:opacity-40 disabled:cursor-not-allowed`;
const TASK_REPORT_MENU_ITEM_CLASS =
  'block w-full text-left px-3 py-2 text-sm font-medium text-base-content hover:bg-base-300/60 hover:text-base-content focus-visible:bg-base-300/60 focus-visible:text-base-content transition-colors';

const ROW_OPERATION_COLUMN_WIDTHS: Record<string, string> = {
  asset_scope: 'min-w-[760px]',
  task: 'min-w-[520px]',
  policy: 'min-w-[300px]',
  task_schedule: 'min-w-[220px]',
  github_task: 'min-w-[220px]',
  github_scheduler: 'min-w-[300px]',
};

export function hasModuleRowOperations(moduleId: string): boolean {
  return Object.hasOwn(ROW_OPERATION_COLUMN_WIDTHS, moduleId);
}

export function getModuleRowOperationColumnWidthClass(moduleId: string): string {
  return ROW_OPERATION_COLUMN_WIDTHS[moduleId] || '';
}

export type ModuleRowOperationActions = {
  syncTaskRow: (id: string, row: any) => void;
  toggleTaskReportExportMenu: (key: string) => void;
  exportTaskRow: (id: string, format: TaskReportExportFormat) => void;
  stopTaskRow: (id: string) => void;
  deleteTaskRow: (id: string) => void;
  restartTaskRow: (id: string) => void;
  openAssetScopeRowActionDialog: (
    action: ModuleAction | null,
    id: string,
    row: any,
    overrides?: JsonValue,
  ) => void;
  openPolicyTaskDialog: (row: any) => void;
  openActionDialog: (action: ModuleAction, payloadOverrides?: JsonValue) => void;
  deletePolicyRow: (id: string) => void;
  recoverTaskScheduleRow: (id: string) => void;
  stopTaskScheduleRow: (id: string) => void;
  deleteTaskScheduleRow: (id: string) => void;
  stopGithubTaskRow: (id: string) => void;
  deleteGithubTaskRow: (id: string) => void;
  recoverGithubSchedulerRow: (id: string) => void;
  stopGithubSchedulerRow: (id: string) => void;
  deleteGithubSchedulerRow: (id: string) => void;
};

export type ModuleRowOperationConfig = {
  assetScopeUpdateAction: ModuleAction | null;
  assetScopeAddScopeAction: ModuleAction | null;
  assetScopeAddSchedulerAction: ModuleAction | null;
  assetScopeAddSiteMonitorAction: ModuleAction | null;
  assetScopeAddWihMonitorAction: ModuleAction | null;
  policyEditAction: ModuleAction | null;
  githubSchedulerUpdateAction: ModuleAction | null;
};

export function ModuleRowOperations({
  moduleId,
  row,
  id,
  taskDone,
  pendingAction,
  taskReportExportBusy,
  taskReportExportMenu,
  config,
  actions,
}: {
  moduleId: string;
  row: any;
  id: string;
  taskDone: boolean;
  pendingAction: string;
  taskReportExportBusy: boolean;
  taskReportExportMenu: string;
  config: ModuleRowOperationConfig;
  actions: ModuleRowOperationActions;
}) {
  const taskPending = Boolean(pendingAction);

  if (moduleId === 'task') {
    return (
      <div className={ROW_OPERATION_GROUP_CLASS}>
        <button
          onClick={() => actions.syncTaskRow(id, row)}
          disabled={taskPending || !taskDone}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          title={taskPending ? '任务操作进行中' : taskDone ? '同步任务数据' : '任务结束后可同步'}
        >
          {pendingAction === 'sync' ? '同步中...' : '同步'}
        </button>
        <div className="relative" data-task-report-export-menu="true">
          <button
            type="button"
            onClick={() => actions.toggleTaskReportExportMenu(`row:${id}`)}
            disabled={taskPending || taskReportExportBusy}
            className={`${ROW_OPERATION_DISABLED_BUTTON_CLASS} flex items-center gap-1`}
          >
            {pendingAction === 'export' || taskReportExportBusy ? '导出中...' : '导出'}
            <ChevronDown className={`w-4 h-4 transition ${taskReportExportMenu === `row:${id}` ? 'rotate-180' : ''}`} />
          </button>
          {taskReportExportMenu === `row:${id}` && !taskPending && !taskReportExportBusy ? (
            <div className="absolute right-0 top-full z-20 mt-2 min-w-[140px] overflow-hidden rounded-box border border-base-300 bg-base-200 shadow-lg">
              {TASK_REPORT_EXPORT_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => actions.exportTaskRow(id, option.value)}
                  className={TASK_REPORT_MENU_ITEM_CLASS}
                >
                  {option.label}
                </button>
              ))}
            </div>
          ) : null}
        </div>
        <button
          onClick={() => actions.stopTaskRow(id)}
          disabled={taskPending || taskDone}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          title={taskPending ? '任务操作进行中' : taskDone ? '任务已结束，无需停止' : '停止任务'}
        >
          {pendingAction === 'stop' ? '停止中...' : '停止'}
        </button>
        <button
          onClick={() => actions.deleteTaskRow(id)}
          disabled={taskPending}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
        >
          {pendingAction === 'delete' ? '删除中...' : '删除'}
        </button>
        <button
          onClick={() => actions.restartTaskRow(id)}
          disabled={taskPending || !taskDone}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          title={taskPending ? '任务操作进行中' : taskDone ? '重启任务' : '任务结束后可重启'}
        >
          {pendingAction === 'restart' ? '重启中...' : '重启'}
        </button>
      </div>
    );
  }

  if (moduleId === 'asset_scope') {
    return (
      <div className={ROW_OPERATION_GROUP_CLASS}>
        {config.assetScopeUpdateAction ? (
          <button
            onClick={() => actions.openAssetScopeRowActionDialog(config.assetScopeUpdateAction, id, row)}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            编辑资产
          </button>
        ) : null}
        {config.assetScopeAddScopeAction ? (
          <button
            onClick={() => actions.openAssetScopeRowActionDialog(config.assetScopeAddScopeAction, id, row, { scope: '' })}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            添加资产分组范围
          </button>
        ) : null}
        {config.assetScopeAddSchedulerAction ? (
          <button
            onClick={() => actions.openAssetScopeRowActionDialog(config.assetScopeAddSchedulerAction, id, row, {
              domain: String(row?.scope || '').replace(/,/g, '\n'),
              name: `监控-${String(row?.name || '').trim() || id.slice(-6)}`,
            })}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            添加监控任务
          </button>
        ) : null}
        {config.assetScopeAddSiteMonitorAction ? (
          <button
            onClick={() => actions.openAssetScopeRowActionDialog(config.assetScopeAddSiteMonitorAction, id, row, {
              name: `站点监控-${String(row?.name || '').trim() || id.slice(-6)}`,
            })}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            添加站点监控任务
          </button>
        ) : null}
        {config.assetScopeAddWihMonitorAction ? (
          <button
            onClick={() => actions.openAssetScopeRowActionDialog(config.assetScopeAddWihMonitorAction, id, row, {
              name: `WIH监控-${String(row?.name || '').trim() || id.slice(-6)}`,
            })}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            添加WIH监控任务
          </button>
        ) : null}
      </div>
    );
  }

  if (moduleId === 'policy') {
    return (
      <div className={ROW_OPERATION_GROUP_CLASS}>
        <button onClick={() => actions.openPolicyTaskDialog(row)} className={ROW_OPERATION_BUTTON_CLASS}>
          任务下发
        </button>
        {config.policyEditAction ? (
          <button
            onClick={() => actions.openActionDialog(config.policyEditAction as ModuleAction, {
              policy_id: id,
              policy_data: {
                name: row?.name || '',
                desc: row?.desc || '',
                policy: row?.policy || {},
              },
            })}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            编辑
          </button>
        ) : null}
        <button
          onClick={() => actions.deletePolicyRow(id)}
          disabled={Boolean(pendingAction)}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
        >
          {pendingAction === 'delete' ? '删除中...' : '删除'}
        </button>
      </div>
    );
  }

  if (moduleId === 'task_schedule') {
    return (
      <div className={ROW_OPERATION_GROUP_CLASS}>
        {String(row?.status || '').toLowerCase() === 'stop' ? (
          <button
            onClick={() => actions.recoverTaskScheduleRow(id)}
            disabled={Boolean(pendingAction)}
            className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          >
            {pendingAction === 'recover' ? '恢复中...' : '恢复'}
          </button>
        ) : (
          <button
            onClick={() => actions.stopTaskScheduleRow(id)}
            disabled={Boolean(pendingAction)}
            className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          >
            {pendingAction === 'stop' ? '停止中...' : '停止'}
          </button>
        )}
        <button
          onClick={() => actions.deleteTaskScheduleRow(id)}
          disabled={Boolean(pendingAction)}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
        >
          {pendingAction === 'delete' ? '删除中...' : '删除'}
        </button>
      </div>
    );
  }

  if (moduleId === 'github_task') {
    return (
      <div className={ROW_OPERATION_GROUP_CLASS}>
        <button
          onClick={() => actions.stopGithubTaskRow(id)}
          disabled={Boolean(pendingAction) || ['done', 'stop', 'error'].includes(String(row?.status || '').toLowerCase())}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          title={pendingAction
            ? '任务操作进行中'
            : ['done', 'stop', 'error'].includes(String(row?.status || '').toLowerCase())
              ? '任务已结束，无需停止'
              : '停止 GitHub 监控任务'}
        >
          {pendingAction === 'stop' ? '停止中...' : '停止'}
        </button>
        <button
          onClick={() => actions.deleteGithubTaskRow(id)}
          disabled={Boolean(pendingAction)}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
        >
          {pendingAction === 'delete' ? '删除中...' : '删除'}
        </button>
      </div>
    );
  }

  if (moduleId === 'github_scheduler') {
    return (
      <div className={ROW_OPERATION_GROUP_CLASS}>
        {config.githubSchedulerUpdateAction ? (
          <button
            onClick={() => actions.openActionDialog(config.githubSchedulerUpdateAction as ModuleAction, {
              _id: id,
              name: row?.name || '',
              keyword: row?.keyword || '',
              cron: row?.cron || '',
              dingding_notify: row?.dingding_notify !== false,
              kb_notify_enable: Boolean(row?.kb_notify_enable),
            })}
            className={ROW_OPERATION_BUTTON_CLASS}
          >
            修改
          </button>
        ) : null}
        {String(row?.status || '').toLowerCase() === 'stop' ? (
          <button
            onClick={() => actions.recoverGithubSchedulerRow(id)}
            disabled={Boolean(pendingAction)}
            className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          >
            {pendingAction === 'recover' ? '恢复中...' : '恢复'}
          </button>
        ) : (
          <button
            onClick={() => actions.stopGithubSchedulerRow(id)}
            disabled={Boolean(pendingAction)}
            className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
          >
            {pendingAction === 'stop' ? '停止中...' : '停止'}
          </button>
        )}
        <button
          onClick={() => actions.deleteGithubSchedulerRow(id)}
          disabled={Boolean(pendingAction)}
          className={ROW_OPERATION_DISABLED_BUTTON_CLASS}
        >
          {pendingAction === 'delete' ? '删除中...' : '删除'}
        </button>
      </div>
    );
  }

  return null;
}
