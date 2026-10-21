import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { TaskReportExportFeedback } from '../../domain/types';
import { SensitiveRevealVerifyModal } from '../../components/domain/SensitiveRevealVerifyModal';
import { RiskRecordDetailModal } from './RiskRecordDetailModal';
import { TaskErrorDialog } from './TaskErrorDialog';
import { TaskReportExportDialog } from './TaskReportExportDialog';

afterEach(cleanup);

describe('模块详情弹窗', () => {
  it('敏感配置验证期间拦截所有关闭入口，完成后允许关闭', () => {
    const onClose = vi.fn();
    const props = {
      open: true,
      title: '进入 Key 编辑模式需要身份验证',
      username: 'admin',
      password: 'secret',
      loading: true,
      error: '',
      onClose,
      onConfirm: vi.fn(),
      onUsernameChange: vi.fn(),
      onPasswordChange: vi.fn(),
    };
    const view = render(<SensitiveRevealVerifyModal {...props} />);
    const dialog = document.querySelector('dialog') as HTMLDialogElement;
    const closeButton = screen.getByTitle('关闭') as HTMLButtonElement;

    expect(closeButton.disabled).toBe(true);
    fireEvent.click(closeButton);
    fireEvent.click(screen.getByRole('button', { name: '取消' }));
    fireEvent.click(dialog);
    fireEvent(dialog, new Event('close'));
    expect(onClose).not.toHaveBeenCalled();

    view.rerender(<SensitiveRevealVerifyModal {...props} loading={false} />);
    fireEvent.click(screen.getByTitle('关闭'));
    expect(onClose).toHaveBeenCalledOnce();
  });

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
    const dialog = document.querySelector('dialog') as HTMLDialogElement;
    const cancelEvent = new Event('cancel', { cancelable: true });
    fireEvent.click(dialog);
    fireEvent(dialog, cancelEvent);
    expect(cancelEvent.defaultPrevented).toBe(true);
    expect(onClose).not.toHaveBeenCalled();

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
    const taskName = 'wih_urlfinder_sensitive_scan_task_processing_stage';
    const taskId = 'task_identifier_with_an_unusually_long_value_for_modal_layout';
    const stage = 'domain_stage_services_ip_cert_service_stage';
    render(
      <TaskErrorDialog
        detail={{
          taskId,
          taskName,
          target: 'example.test',
          logs: [{ time: '13:05', stage, message: '请求超时', traceback: 'TimeoutError' }],
        }}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByText('任务异常详情')).toBeTruthy();
    expect(screen.getByText(taskName).className).toContain('break-all');
    expect(screen.getByText(taskId).className).toContain('break-all');
    expect(screen.getByText(stage).className).toContain('break-all');
    expect(screen.getByText('TimeoutError')).toBeTruthy();
  });
});
