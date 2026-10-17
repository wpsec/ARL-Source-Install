import { HoverCellValue } from '../../components/ui/HoverCellValue';
import { CONSOLE_TEXT_BUTTON_CLASS } from '../../ui/classes';

export function ExpandableMetadataCell({
  text,
  copyText,
  label,
  expanded,
  onToggle,
  onCopy,
  columnStyle,
}: {
  text: string;
  copyText: string;
  label: string;
  expanded: boolean;
  onToggle: () => void;
  onCopy: (text: string, label?: string) => void | Promise<void>;
  columnStyle?: React.CSSProperties;
}) {
  const lines = String(text || '')
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item && item !== '-');
  const shouldCollapse = lines.length > 3;
  const renderedText = shouldCollapse && !expanded
    ? `${lines.slice(0, 3).join('\n')}\n...`
    : (lines.length > 0 ? lines.join('\n') : '-');
  const completeText = copyText !== '-' ? copyText : text;

  return (
    <td
      className="px-4 py-3 align-middle text-sm text-left whitespace-pre-wrap break-all leading-relaxed min-w-0 max-w-full"
      style={columnStyle}
    >
      <HoverCellValue
        display={(
          <div className={`whitespace-pre-wrap break-all leading-relaxed ${shouldCollapse && !expanded ? 'max-h-24 overflow-hidden' : ''}`}>
            {renderedText}
          </div>
        )}
        fullText={completeText}
        label={label}
        onCopy={onCopy}
        showHover={copyText !== '-' || text !== '-'}
        forceHover={shouldCollapse && !expanded}
      />
      {shouldCollapse ? (
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          className={`${CONSOLE_TEXT_BUTTON_CLASS} mt-2 text-left text-xs font-semibold text-accent hover:underline`}
        >
          {expanded ? '收起' : '展开'}
        </button>
      ) : null}
    </td>
  );
}
