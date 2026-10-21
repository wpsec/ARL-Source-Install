import { Badge } from './Badge';

export function StatusPill({
  text,
  type,
  compact = false,
}: {
  text: string;
  type: 'success' | 'error' | 'info';
  compact?: boolean;
}) {
  return (
    <Badge
      tone={type}
      title={text}
      className={`h-auto rounded-full px-3 py-1 font-semibold leading-relaxed ${compact ? 'min-w-0 max-w-full overflow-hidden whitespace-nowrap' : 'max-w-[72vw] whitespace-normal break-words md:max-w-[36rem]'}`}
    >
      <span className={compact ? 'block min-w-0 max-w-full truncate' : 'min-w-0 whitespace-pre-wrap break-words'}>{text}</span>
    </Badge>
  );
}
