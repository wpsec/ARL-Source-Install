import React from 'react';
import { AlertTriangle } from 'lucide-react';
import {
  buildTaskExecutionAccountingSummary,
  buildTaskExecutionDurationInfo,
  buildTaskServiceDurationSummary,
} from '../../domain/task';
import { CONSOLE_TEXT_BUTTON_CLASS } from '../../ui/classes';

export function TaskExecutionStatusCell({
  row,
  statusText,
  columnStyle,
  onOpenError,
}: {
  row: any;
  statusText: string;
  columnStyle?: React.CSSProperties;
  onOpenError: (row: any) => void;
}) {
  const rawStatus = String(row?.status || '').trim().toLowerCase();
  const durationDetail = buildTaskExecutionDurationInfo(row, Date.now());
  const taskServiceDuration = buildTaskServiceDurationSummary(row);
  const taskAccountingSummary = buildTaskExecutionAccountingSummary(row, Date.now());
  const currentDurationLabel = durationDetail.durationLabel || '-';
  const visibleStatusText = rawStatus === 'done' && currentDurationLabel !== '-'
    ? `${statusText}（${currentDurationLabel}）`
    : statusText;
  const statusNode = rawStatus === 'error' ? (
    <button
      type="button"
      onClick={() => onOpenError(row)}
      className={`${CONSOLE_TEXT_BUTTON_CLASS} inline-flex min-w-0 max-w-full items-center gap-1 font-semibold text-error hover:underline`}
      title="点击查看异常详情"
    >
      <AlertTriangle className="h-4 w-4" />
      <span className="block min-w-0 max-w-full truncate">{visibleStatusText}</span>
    </button>
  ) : (
    <span className="block min-w-0 max-w-full truncate">{visibleStatusText}</span>
  );

  return (
    <td className="arl-table-popover-cell min-w-0 max-w-full overflow-hidden whitespace-nowrap px-4 py-3 text-center align-middle text-sm" style={columnStyle}>
      <div className="group relative flex min-w-0 max-w-full items-center justify-center">
        {statusNode}
        <div className="pointer-events-none invisible absolute left-1/2 top-full z-30 w-[420px] max-w-[82vw] -translate-x-1/2 pt-2 opacity-0 transition duration-150 delay-300 group-hover:pointer-events-auto group-hover:visible group-hover:opacity-100">
          <div className="rounded-box border border-base-300 bg-base-200 p-3 text-left shadow-lg">
            <h3 className="text-xs font-semibold tracking-wide text-base-content">任务执行时间概览</h3>
            <div className="mt-2 rounded-box border border-base-300 bg-base-100 px-2.5 py-2">
              <div className="text-[11px] text-content-muted">当前任务执行时长</div>
              <div className="mt-1 text-sm font-semibold text-base-content">{currentDurationLabel}</div>
              <div className="mt-1 text-[11px] text-content-muted">开始：{durationDetail.startText || '-'}</div>
              <div className="text-[11px] text-content-muted">结束：{durationDetail.endText || '-'}</div>
            </div>
            <div className="mt-2 text-[11px] text-content-muted">
              已记录子任务阶段 {taskServiceDuration.totalStageCount} 个，可统计耗时 {taskServiceDuration.countedStageCount} 个
            </div>
            <div className="text-[11px] text-content-muted">子任务累计耗时：{taskServiceDuration.totalDurationLabel}</div>
            {taskServiceDuration.dedupApplied ? (
              <div className="whitespace-pre-line text-[11px] text-content-muted">
                已自动排除父阶段重复统计
                {taskServiceDuration.skippedParentStageNames.length
                  ? `：\n${taskServiceDuration.skippedParentStageNames.join('\n')}`
                  : ''}
              </div>
            ) : null}
            {taskAccountingSummary.currentStageVisible ? (
              <div className="text-[11px] text-content-muted">当前进行阶段：{taskAccountingSummary.currentStageName}</div>
            ) : null}
            {taskAccountingSummary.hasUncountedDuration ? (
              <div className="text-[11px] font-semibold text-warning">
                进行中阶段耗时（暂未计入累计）：{taskAccountingSummary.uncountedStageName} · {taskAccountingSummary.uncountedDurationLabel}
              </div>
            ) : null}
            {taskAccountingSummary.note ? (
              <p className="mt-1 text-[11px] text-content-muted">{taskAccountingSummary.note}</p>
            ) : null}
            <div className="mt-2 max-h-44 overflow-y-auto rounded-box border border-base-300 bg-base-100 p-2 text-[11px] leading-relaxed text-base-content">
              {taskServiceDuration.entries.length > 0 ? (
                taskServiceDuration.entries.map((entry, index) => (
                  <React.Fragment key={`${index}-${entry.stageName}`}>
                    <div className="break-all font-mono">
                      {`${index + 1}. ${entry.stageName}：${entry.elapsedLabel}${entry.countedInTotal ? '' : '（汇总阶段，未计入累计耗时）'}`}
                    </div>
                    {entry.detail ? <div className="break-all pl-4 text-content-muted">{entry.detail}</div> : null}
                  </React.Fragment>
                ))
              ) : <div className="text-content-muted">暂无该任务子任务执行时间数据</div>}
            </div>
          </div>
        </div>
      </div>
    </td>
  );
}
