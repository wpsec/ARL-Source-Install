import { X } from 'lucide-react';
import { Modal } from '../../components/ui/Modal';
import { humanizeField, normalizeValueNoTruncate } from '../../domain/format';
import { CONSOLE_ICON_BUTTON_CLASS, CONSOLE_TEXT_BUTTON_CLASS } from '../../ui/classes';

export type RiskRecordDetail = {
  moduleId: string;
  rowId: string;
  rowTitle: string;
  row: Record<string, any>;
};

export function RiskRecordDetailModal({
  detail,
  onClose,
  onCopy,
}: {
  detail: RiskRecordDetail;
  onClose: () => void;
  onCopy: (text: string, label?: string) => void | Promise<void>;
}) {
  const detailRow = detail.row || {};
  const isNuclei = detail.moduleId === 'nuclei_result';
  const knownKeys = isNuclei
    ? ['scanner_type', 'rule_id', 'vuln_name', 'vuln_severity', 'severity', 'target', 'vuln_url', 'matched', 'extracted_results', 'save_date']
    : ['vul_name', 'plg_type', 'app_name', 'target', 'credential', 'save_date', 'source'];
  const usedKeys = new Set<string>([
    ...knownKeys,
    '_id', 'task_id', 'task_cid', 'time',
    'ai_analysis', 'ai_analysis_reason', 'ai_fill',
    'verify_data', 'request', 'headers',
  ]);
  const fields: Array<[string, string]> = [];
  knownKeys.forEach((key) => {
    const text = normalizeValueNoTruncate(detailRow[key]);
    if (text && text !== '-' && text !== '[]' && text !== '{}') {
      fields.push([humanizeField(key), text]);
    }
  });
  Object.keys(detailRow).forEach((key) => {
    if (usedKeys.has(key)) return;
    const value = detailRow[key];
    if (value === null || value === undefined || value === '') return;
    if (typeof value === 'object') return;
    const text = String(value);
    if (!text || text === '-') return;
    fields.push([humanizeField(key), text]);
  });
  const verifyRaw = normalizeValueNoTruncate(detailRow.verify_data);
  const verifyScanner = String(detailRow?.scanner_type || '').trim().toLowerCase();
  const verifyLabel = verifyScanner === 'afrog' ? 'afrog curl命令' : '验证报文';

  return (
    <Modal open onClose={onClose} boxClass="w-full max-w-5xl!">
      <div className="px-6 py-4 border-b border-base-300 flex items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <h4 className="text-lg font-black">{isNuclei ? 'PoC风险详情' : '风险详情'}</h4>
          <p className="text-sm font-semibold break-all">{detail.rowTitle || '-'}</p>
        </div>
        <button type="button" onClick={onClose} className={CONSOLE_ICON_BUTTON_CLASS} title="关闭">
          <X className="w-5 h-5" />
        </button>
      </div>
      <div className="p-6 space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {fields.map(([label, text]) => (
            <div key={label} className="rounded-box border border-base-300 bg-base-100 px-4 py-3">
              <div className="text-xs font-semibold text-content-muted mb-1">{label}</div>
              <div className="text-sm break-all whitespace-pre-wrap">{text}</div>
            </div>
          ))}
        </div>
        {verifyRaw && verifyRaw !== '-' ? (
          <div className="rounded-box border border-base-300 bg-base-100 px-4 py-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-content-muted">{verifyLabel}</span>
              <button
                type="button"
                onClick={() => void onCopy(verifyRaw, verifyLabel)}
                className={`${CONSOLE_TEXT_BUTTON_CLASS} text-xs font-semibold text-accent hover:underline`}
              >
                复制
              </button>
            </div>
            <pre className="whitespace-pre-wrap break-all leading-relaxed font-mono text-sm max-h-[40vh] overflow-auto">{verifyRaw}</pre>
          </div>
        ) : null}
      </div>
    </Modal>
  );
}
