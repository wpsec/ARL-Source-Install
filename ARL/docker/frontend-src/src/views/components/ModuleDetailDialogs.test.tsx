import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { TaskReportExportFeedback } from '../../domain/types';
import { RiskRecordDetailModal } from './RiskRecordDetailModal';
import { TaskErrorDialog } from './TaskErrorDialog';
import { TaskReportExportDialog } from './TaskReportExportDialog';

afterEach(cleanup);

describe('模块详情弹窗', () => {
  it('风险详情保留字段提取和验证内容复制标签', () => {
    const onCopy = vi.fn();
    render(
      <RiskRecordDetailModal
        detail={{
          moduleId: 'nuclei_result',
          rowId: 'risk-3',
          rowTitle: 'SQL injection',
          row: {
            vuln_name: 'SQL injection',
            target: 'https://example.test/item',
            scanner_type: 'afrog',
            verify_data: 'curl https://example.test/item',
            extra_scalar: '保留的扩展字段',
          },
        }}
        onClose={vi.fn()}
        onCopy={onCopy}
      />,
    );

    expect(screen.getByText('PoC风险详情')).toBeTruthy();
    expect(screen.getAllByText('SQL injection')).toHaveLength(2);
    expect(screen.getByText('保留的扩展字段')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '复制' }));
    expect(onCopy).toHaveBeenCalledWith('curl https://example.test/item', 'afrog curl命令');
  });

  it('报告导出进行中禁止关闭，结束后显示反馈并允许关闭', () => {
    const feedback: TaskReportExportFeedback = {
      phase: 'running',
      progress: 62,
      title: '表格报告导出',
      summary: '正在生成导出文件',
      detail: '导出任务 ID: job-1',
      formatLabel: '表格',
      taskCount: 2,
      jobId: 'job-1',
      fileName: '',
      error: '',
    };
    const onClose = vi.fn();
    const view = render(<TaskReportExportDialog feedback={feedback} busy onClose={onClose} />);
    expect((screen.getByRole('button', { name: '知道了' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole('progressbar', { name: '导出进度' }).getAttribute('value')).toBe('62');

    view.rerender(
      <TaskReportExportDialog
        feedback={{ ...feedback, phase: 'success', progress: 100, summary: '导出成功' }}
        busy={false}
        onClose={onClose}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: '知道了' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('任务异常详情显示阶段和 traceback', () => {
    render(
      <TaskErrorDialog
        detail={{
          taskId: 'task-9',
          taskName: '深度扫描',
          target: 'example.test',
          logs: [{ time: '13:05', stage: 'deep_scan', message: '请求超时', traceback: 'TimeoutError' }],
        }}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByText('任务异常详情')).toBeTruthy();
    expect(screen.getByText('deep_scan')).toBeTruthy();
    expect(screen.getByText('TimeoutError')).toBeTruthy();
  });
});
