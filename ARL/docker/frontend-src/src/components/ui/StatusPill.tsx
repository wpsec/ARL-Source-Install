import { Badge } from './Badge';

export function StatusPill({ text, type }: { text: string; type: 'success' | 'error' | 'info' }) {
  return (
    <Badge tone={type} title={text} className="h-auto max-w-[72vw] whitespace-normal break-words rounded-full px-3 py-1 font-semibold leading-relaxed md:max-w-[36rem]">
      <span className="min-w-0 whitespace-pre-wrap break-words">{text}</span>
    </Badge>
  );
}
