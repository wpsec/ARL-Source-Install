import { CHECKBOX_CARD_CLASS } from '../components/ui/CheckboxCard';

export const UNIFIED_SELECT_CLASS =
  'w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm text-base-content appearance-none pr-9 ' +
  'focus:outline-none focus:border-accent transition';

export const CONSOLE_INPUT_CLASS =
  'w-full h-10 rounded-xl border border-base-300 bg-base-100 px-3 text-sm text-base-content ' +
  'focus:outline-none focus:border-accent transition';

export const CONSOLE_SELECT_CLASS = `${UNIFIED_SELECT_CLASS} h-10`;

export const CONSOLE_INPUT_MONO_CLASS = `${CONSOLE_INPUT_CLASS} font-mono`;

export const CONSOLE_TEXTAREA_MONO_CLASS =
  'w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm text-base-content font-mono ' +
  'focus:outline-none focus:border-accent transition resize-y';

export const CONSOLE_FILE_INPUT_CLASS =
  'flex-1 h-10 rounded-xl border border-base-300 bg-base-100 px-3 text-sm text-base-content ' +
  'focus:outline-none focus:border-accent transition';

export const CONSOLE_CHECKBOX_CARD_CLASS = CHECKBOX_CARD_CLASS;
