import { CHECKBOX_CARD_CLASS } from '../components/ui/CheckboxCard';

export const UNIFIED_SELECT_CLASS =
  'select select-bordered w-full border border-base-300 bg-base-100 text-sm text-base-content appearance-none pr-9';

export const CONSOLE_INPUT_CLASS =
  'input input-bordered w-full h-10 border border-base-300 bg-base-100 text-sm text-base-content';

export const CONSOLE_SELECT_CLASS = `${UNIFIED_SELECT_CLASS} h-10`;

export const CONSOLE_INPUT_MONO_CLASS = `${CONSOLE_INPUT_CLASS} font-mono`;

export const CONSOLE_TEXTAREA_MONO_CLASS =
  'textarea textarea-bordered w-full border border-base-300 bg-base-100 text-sm text-base-content font-mono resize-y';

export const CONSOLE_FILE_INPUT_CLASS =
  'file-input file-input-bordered flex-1 h-10 border border-base-300 bg-base-100 text-sm text-base-content';

export const CONSOLE_PAGE_CLASS = 'min-w-0 w-full max-w-[1920px] mx-auto p-4 sm:p-6 xl:p-8 space-y-6';

export const CONSOLE_BUTTON_CLASS = 'btn btn-sm h-10 min-h-10 whitespace-nowrap';

export const CONSOLE_ICON_BUTTON_CLASS =
  'btn btn-sm btn-square border border-base-300 bg-base-100 text-base-content hover:border-primary/45 hover:bg-base-300/70 hover:text-base-content';

export const CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS =
  'btn btn-sm h-8 min-h-8 whitespace-nowrap border border-base-300 bg-base-100 px-2.5 text-xs text-base-content hover:border-primary/45 hover:bg-base-200 hover:text-base-content';

export const CONSOLE_TEXT_BUTTON_CLASS =
  'border-0 bg-transparent p-0 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45 focus-visible:ring-offset-1 focus-visible:ring-offset-base-100 disabled:cursor-not-allowed disabled:opacity-50';

export const CONSOLE_PRIMARY_BUTTON_CLASS = `${CONSOLE_BUTTON_CLASS} btn-primary`;

export const CONSOLE_SECONDARY_BUTTON_CLASS =
  `${CONSOLE_BUTTON_CLASS} border border-base-300 bg-base-100 text-base-content hover:border-primary/45 hover:bg-base-300/70 hover:text-base-content`;

export const CONSOLE_CARD_ACTION_CLASS =
  'flex h-auto min-h-0 w-full min-w-0 items-start justify-start rounded-box border border-base-300 bg-base-100 text-left text-base-content transition-colors hover:border-primary/45 hover:bg-base-200 hover:text-base-content focus-visible:outline-none';

export const CONSOLE_CHECKBOX_CARD_CLASS = CHECKBOX_CARD_CLASS;

// 统一控制台的信息层级，避免各页面用不同的自定义边框表达相同状态。
export const CONSOLE_PANEL_CLASS =
  'card card-border border border-base-300/85 bg-base-200/90 shadow-sm backdrop-blur-sm';

export const CONSOLE_ALERT_ERROR_CLASS = 'alert alert-error alert-soft text-sm';

export const CONSOLE_ALERT_SUCCESS_CLASS = 'alert alert-success alert-soft text-sm';

export const CONSOLE_ALERT_WARNING_CLASS = 'alert alert-warning alert-soft text-sm';
