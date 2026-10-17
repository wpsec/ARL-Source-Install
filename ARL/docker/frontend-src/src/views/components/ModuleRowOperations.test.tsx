import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ModuleAction } from '../../domain/types';
import {
  ModuleRowOperations,
  type ModuleRowOperationConfig,
} from './ModuleRowOperations';

const createActions = () => ({
  syncTaskRow: vi.fn(),
  toggleTaskReportExportMenu: vi.fn(),
  exportTaskRow: vi.fn(),
  stopTaskRow: vi.fn(),
  deleteTaskRow: vi.fn(),
  restartTaskRow: vi.fn(),
  openAssetScopeRowActionDialog: vi.fn(),
  openPolicyTaskDialog: vi.fn(),
  openActionDialog: vi.fn(),
  deletePolicyRow: vi.fn(),
  recoverTaskScheduleRow: vi.fn(),
  stopTaskScheduleRow: vi.fn(),
  deleteTaskScheduleRow: vi.fn(),
  stopGithubTaskRow: vi.fn(),
  deleteGithubTaskRow: vi.fn(),
  recoverGithubSchedulerRow: vi.fn(),
  stopGithubSchedulerRow: vi.fn(),
  deleteGithubSchedulerRow: vi.fn(),
});

const emptyConfig = {
  assetScopeUpdateAction: null,
  assetScopeAddScopeAction: null,
  assetScopeAddSchedulerAction: null,
  assetScopeAddSiteMonitorAction: null,
  assetScopeAddWihMonitorAction: null,
  policyEditAction: null,
  githubSchedulerUpdateAction: null,
};

function renderOperations({
  moduleId,
  row = {},
  id = 'row-1',
  taskDone = false,
  pendingAction = '',
  taskReportExportBusy = false,
  taskReportExportMenu = '',
  config = emptyConfig,
  actions = createActions(),
}: {
  moduleId: string;
  row?: Record<string, unknown>;
  id?: string;
  taskDone?: boolean;
  pendingAction?: string;
  taskReportExportBusy?: boolean;
  taskReportExportMenu?: string;
  config?: ModuleRowOperationConfig;
  actions?: ReturnType<typeof createActions>;
}) {
  const view = render(
    <ModuleRowOperations
      moduleId={moduleId}
      row={row}
      id={id}
      taskDone={taskDone}
      pendingAction={pendingAction}
      taskReportExportBusy={taskReportExportBusy}
      taskReportExportMenu={taskReportExportMenu}
      config={config}
      actions={actions}
    />,
  );
  return { ...view, actions };
}

afterEach(cleanup);

describe('ModuleRowOperations', () => {
  it('任务终态控制同步和停止，并将导出格式交给任务操作', () => {
    const view = renderOperations({ moduleId: 'task', id: 'task-7', taskDone: false });
    expect((screen.getByRole('button', { name: '同步' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: '停止' }) as HTMLButtonElement).disabled).toBe(false);

    view.rerender(
      <ModuleRowOperations
        moduleId="task"
        row={{ _id: 'task-7' }}
        id="task-7"
        taskDone
        pendingAction=""
        taskReportExportBusy={false}
        taskReportExportMenu="row:task-7"
        config={emptyConfig}
        actions={view.actions}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: '表格格式' }));
    expect(view.actions.exportTaskRow).toHaveBeenCalledWith('task-7', 'excel');
  });

  it('资产组添加监控时保留名称与范围默认值', () => {
    const action: ModuleAction = {
      id: 'asset_scope_add_scheduler',
      label: '添加监控任务',
      method: 'POST',
      path: '/asset_scope/add_scheduler/',
    };
    const row = { name: '生产资产', scope: 'example.com,example.org' };
    const view = renderOperations({
      moduleId: 'asset_scope',
      id: 'scope-4',
      row,
      config: { ...emptyConfig, assetScopeAddSchedulerAction: action },
    });

    fireEvent.click(screen.getByRole('button', { name: '添加监控任务' }));
    expect(view.actions.openAssetScopeRowActionDialog).toHaveBeenCalledWith(action, 'scope-4', row, {
      domain: 'example.com\nexample.org',
      name: '监控-生产资产',
    });
  });
});
