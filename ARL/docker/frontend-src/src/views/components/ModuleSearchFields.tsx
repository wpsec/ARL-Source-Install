import { ChevronDown } from 'lucide-react';
import type { ModuleSearchField } from '../../domain/types';
import { CONSOLE_INPUT_CLASS, UNIFIED_SELECT_CLASS } from '../../ui/classes';

type SearchOption = { label: string; value: string };

export function ModuleSearchFields({
  moduleId,
  fields,
  values,
  getOptions,
  getSuggestions,
  onChange,
  onEnter,
}: {
  moduleId: string;
  fields: ModuleSearchField[];
  values: Record<string, unknown>;
  getOptions: (field: ModuleSearchField) => SearchOption[];
  getSuggestions: (field: ModuleSearchField) => SearchOption[];
  onChange: (key: string, value: string) => void;
  onEnter: () => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
      {fields.map((field) => {
        const fieldId = `module-search-${moduleId}-${field.key}`;
        const value = String(values[field.key] ?? '');
        if (field.inputType === 'select') {
          return (
            <div key={field.key} className="space-y-1">
              <label htmlFor={fieldId} className="text-xs font-semibold text-base-content">{field.label}：</label>
              <div className="relative">
                <select
                  id={fieldId}
                  value={value}
                  className={UNIFIED_SELECT_CLASS}
                  onChange={(event) => onChange(field.key, event.target.value)}
                >
                  {getOptions(field).map((option) => (
                    <option key={`${field.key}-${option.value}`} value={option.value}>{option.label}</option>
                  ))}
                </select>
                <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-base-content" />
              </div>
            </div>
          );
        }

        const suggestions = getSuggestions(field);
        const datalistId = suggestions.length > 0 ? `search-suggestions-${moduleId}-${field.key}` : undefined;
        return (
          <div key={field.key} className="space-y-1">
            <label htmlFor={fieldId} className="text-xs font-semibold text-base-content">{field.label}：</label>
            <input
              id={fieldId}
              list={datalistId}
              type={field.inputType === 'number' ? 'number' : 'text'}
              value={value}
              placeholder={field.placeholder}
              className={`${CONSOLE_INPUT_CLASS} placeholder:text-content-muted`}
              onChange={(event) => onChange(field.key, event.target.value)}
              onKeyDown={(event) => {
                if (event.key !== 'Enter') return;
                event.preventDefault();
                onEnter();
              }}
            />
            {datalistId ? (
              <datalist id={datalistId}>
                {suggestions.map((option) => (
                  <option key={`${field.key}-${option.value}`} value={option.value}>{option.label}</option>
                ))}
              </datalist>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
