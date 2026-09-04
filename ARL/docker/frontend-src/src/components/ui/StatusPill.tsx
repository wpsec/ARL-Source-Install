import { Badge } from './Badge';

export function StatusPill({ text, type }: { text: string; type: 'success' | 'error' | 'info' }) {
  return (
    <Badge tone={type} title={text} className="max-w-[72vw] md:max-w-[36rem] rounded-full px-3 py-1 font-semibold">
      <span className="truncate">{text}</span>
    </Badge>
  );
}
