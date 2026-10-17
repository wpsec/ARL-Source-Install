import { AlertTriangle, X } from 'lucide-react';
import { Modal } from '../../components/ui/Modal';
import { CONSOLE_ICON_BUTTON_CLASS, CONSOLE_SECONDARY_BUTTON_CLASS } from '../../ui/classes';

export type TaskErrorDetail = {
  taskId: string;
  taskName: string;
  target: string;
  logs: Array<{
    time: string;
    stage: string;
    message: string;
    traceback: string;
  }>;
};

export function TaskErrorDialog({ detail, onClose }: { detail: TaskErrorDetail; onClose: () => void }) {
  return (
    <Modal open onClose={onClose} boxClass="w-full max-w-5xl!">
      <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-error" />
          <h4 className="text-lg font-black">任务异常详情</h4>
        </div>
        <button onClick={onClose} className={CONSOLE_ICON_BUTTON_CLASS} title="关闭">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="shrink-0 min-w-0 px-6 py-4 border-b border-base-300 bg-base-100 text-sm space-y-1">
        <div><span className="text-content-muted">任务名：</span>{detail.taskName}</div>
        <div><span className="text-content-muted">目标：</span><span className="font-mono break-all">{detail.target}</span></div>
        <div><span className="text-content-muted">Task_ID：</span><span className="font-mono">{detail.taskId || '-'}</span></div>
      </div>

      <div className="min-h-0 min-w-0 flex-1 p-6 overflow-y-auto overflow-x-hidden custom-scrollbar space-y-4">
        {detail.logs.length > 0 ? detail.logs.map((log, index) => (
          <div key={`${log.time}-${log.stage}-${index}`} className="rounded-box border border-base-300 bg-base-100 p-4 space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              <div><span className="text-content-muted">时间：</span><span className="font-mono">{log.time || '-'}</span></div>
              <div><span className="text-content-muted">阶段：</span><span className="font-mono">{log.stage || '-'}</span></div>
            </div>
            <div className="text-sm">
              <span className="text-content-muted">异常说明：</span>
              <div className="mt-1 whitespace-pre-wrap break-all leading-relaxed">{log.message || '-'}</div>
            </div>
            {log.traceback ? (
              <div className="text-sm">
                <span className="text-content-muted">日志信息：</span>
                <pre className="mt-1 whitespace-pre-wrap break-all leading-relaxed font-mono text-xs bg-base-100 border border-base-300 rounded-box p-3 overflow-auto">{log.traceback}</pre>
              </div>
            ) : null}
          </div>
        )) : (
          <div className="text-sm text-content-muted">
            当前任务没有记录到详细异常日志（可能是历史任务或异常详情落库前的任务）。
          </div>
        )}
      </div>
      <div className="shrink-0 min-w-0 flex justify-end border-t border-base-300 bg-base-100 px-6 py-4">
        <button type="button" onClick={onClose} className={`${CONSOLE_SECONDARY_BUTTON_CLASS} w-full sm:w-auto`}>
          关闭
        </button>
      </div>
    </Modal>
  );
}
