import { AlertTriangle, CheckCircle2, RefreshCw, X } from 'lucide-react';
import { Modal } from '../../components/ui/Modal';
import type { TaskReportExportFeedback } from '../../domain/types';
import {
  CONSOLE_ALERT_ERROR_CLASS,
  CONSOLE_ALERT_INFO_CLASS,
  CONSOLE_ALERT_SUCCESS_CLASS,
  CONSOLE_ICON_BUTTON_CLASS,
  CONSOLE_SECONDARY_BUTTON_CLASS,
} from '../../ui/classes';

export function TaskReportExportDialog({
  feedback,
  busy,
  onClose,
}: {
  feedback: TaskReportExportFeedback;
  busy: boolean;
  onClose: () => void;
}) {
  const closeWhenIdle = () => {
    if (!busy) onClose();
  };
  const alertClass = feedback.phase === 'error'
    ? CONSOLE_ALERT_ERROR_CLASS
    : feedback.phase === 'success'
      ? CONSOLE_ALERT_SUCCESS_CLASS
      : CONSOLE_ALERT_INFO_CLASS;
  const progressClass = feedback.phase === 'error'
    ? 'progress-error'
    : feedback.phase === 'success'
      ? 'progress-success'
      : 'progress-primary';

  return (
    <Modal open onClose={closeWhenIdle} boxClass="w-full max-w-lg!">
      <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h4 className="text-lg font-black">{feedback.title}</h4>
          <p className="text-xs text-content-muted mt-1 break-all">
            {feedback.jobId ? `导出任务 ID: ${feedback.jobId}` : '正在初始化导出任务'}
          </p>
        </div>
        <button
          onClick={onClose}
          disabled={busy}
          className={`${CONSOLE_ICON_BUTTON_CLASS} disabled:opacity-40`}
          title={busy ? '导出进行中，暂不可关闭' : '关闭'}
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden custom-scrollbar p-6 space-y-4">
        <div role={feedback.phase === 'error' ? 'alert' : 'status'} className={`${alertClass} px-4 py-3`}>
          <div className="flex items-start gap-3">
            <div className="mt-0.5 shrink-0">
              {feedback.phase === 'success' ? (
                <CheckCircle2 className="w-5 h-5 text-success" />
              ) : feedback.phase === 'error' ? (
                <AlertTriangle className="w-5 h-5 text-error" />
              ) : (
                <RefreshCw className="w-5 h-5 text-accent animate-spin" />
              )}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-black break-all">{feedback.summary}</p>
              <p className="text-xs mt-1 break-all opacity-90">{feedback.detail}</p>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-semibold text-content-muted">
            <span>导出进度</span>
            <span>{feedback.progress}%</span>
          </div>
          <progress
            className={`progress w-full ${progressClass}`}
            value={Math.max(0, Math.min(100, feedback.progress))}
            max="100"
            aria-label="导出进度"
          />
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="rounded-box border border-base-300 bg-base-100 px-3 py-2">
            <div className="text-content-muted">任务数量</div>
            <div className="mt-1 font-semibold text-sm">{feedback.taskCount}</div>
          </div>
          <div className="rounded-box border border-base-300 bg-base-100 px-3 py-2">
            <div className="text-content-muted">导出格式</div>
            <div className="mt-1 font-semibold text-sm break-all">{feedback.formatLabel}</div>
          </div>
        </div>

        {feedback.fileName ? (
          <div className="rounded-box border border-base-300 bg-base-100 px-3 py-2">
            <div className="text-xs text-content-muted">导出文件</div>
            <div className="mt-1 text-sm font-semibold break-all">{feedback.fileName}</div>
          </div>
        ) : null}

        {feedback.error ? (
          <div role="alert" className={`${CONSOLE_ALERT_ERROR_CLASS} whitespace-pre-wrap break-all`}>
            {feedback.error}
          </div>
        ) : null}

        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-content-muted">{busy ? '导出进行中，请稍候...' : '导出流程已结束'}</p>
        </div>
      </div>
      <div className="shrink-0 flex flex-col gap-2 border-t border-base-300 bg-base-100 px-6 py-4 sm:flex-row sm:items-center sm:justify-end">
        <button
          onClick={onClose}
          disabled={busy}
          className={`${CONSOLE_SECONDARY_BUTTON_CLASS} w-full disabled:opacity-40 sm:w-auto`}
        >
          {feedback.phase === 'error' ? '关闭' : '知道了'}
        </button>
      </div>
    </Modal>
  );
}
