import { useState } from 'react';
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
  const [activeSuggestionField, setActiveSuggestionField] = useState('');
  const [activeSuggestionIndex, setActiveSuggestionIndex] = useState(-1);

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
        const suggestionListId = `search-suggestions-${moduleId}-${field.key}`;
        const filteredSuggestions = suggestions
          .filter((option) => option.label.toLocaleLowerCase().includes(value.toLocaleLowerCase()))
          .slice(0, 25);
        const showSuggestions = suggestions.length > 0
          && activeSuggestionField === field.key
          && filteredSuggestions.length > 0;
        const setSelectedSuggestion = (option: SearchOption) => {
          onChange(field.key, option.value);
          setActiveSuggestionField('');
          setActiveSuggestionIndex(-1);
        };
        return (
          <div key={field.key} className="space-y-1">
            <label htmlFor={fieldId} className="text-xs font-semibold text-base-content">{field.label}：</label>
            <div className="relative">
              <input
                id={fieldId}
                type={field.inputType === 'number' ? 'number' : 'text'}
                value={value}
                placeholder={field.placeholder}
                className={`${CONSOLE_INPUT_CLASS} placeholder:text-content-muted`}
                autoComplete={suggestions.length > 0 ? 'off' : undefined}
                role={suggestions.length > 0 ? 'combobox' : undefined}
                aria-autocomplete={suggestions.length > 0 ? 'list' : undefined}
                aria-expanded={suggestions.length > 0 ? showSuggestions : undefined}
                aria-controls={suggestions.length > 0 ? suggestionListId : undefined}
                aria-activedescendant={activeSuggestionIndex >= 0 && showSuggestions
                  ? `${suggestionListId}-option-${activeSuggestionIndex}`
                  : undefined}
                onFocus={() => {
                  if (suggestions.length === 0) return;
                  setActiveSuggestionField(field.key);
                  setActiveSuggestionIndex(-1);
                }}
                onBlur={() => {
                  setActiveSuggestionField((current) => current === field.key ? '' : current);
                  setActiveSuggestionIndex(-1);
                }}
                onChange={(event) => {
                  onChange(field.key, event.target.value);
                  if (suggestions.length > 0) {
                    setActiveSuggestionField(field.key);
                    setActiveSuggestionIndex(-1);
                  }
                }}
                onKeyDown={(event) => {
                  if (showSuggestions && event.key === 'ArrowDown') {
                    event.preventDefault();
                    setActiveSuggestionIndex((current) => (current + 1) % filteredSuggestions.length);
                    return;
                  }
                  if (showSuggestions && event.key === 'ArrowUp') {
                    event.preventDefault();
                    setActiveSuggestionIndex((current) => (
                      current <= 0 ? filteredSuggestions.length - 1 : current - 1
                    ));
                    return;
                  }
                  if (showSuggestions && event.key === 'Enter' && activeSuggestionIndex >= 0) {
                    event.preventDefault();
                    setSelectedSuggestion(filteredSuggestions[activeSuggestionIndex]);
                    return;
                  }
                  if (event.key === 'Escape' && showSuggestions) {
                    event.preventDefault();
                    setActiveSuggestionField('');
                    setActiveSuggestionIndex(-1);
                    return;
                  }
                  if (event.key === 'Enter') {
                    event.preventDefault();
                    onEnter();
                  }
                }}
              />
              {showSuggestions ? (
                <div
                  id={suggestionListId}
                  role="listbox"
                  aria-label={`${field.label}候选项`}
                  className="absolute inset-x-0 top-full z-50 mt-1 max-h-56 overflow-y-auto rounded-box border border-base-300 bg-base-100 p-1 shadow-lg"
                >
                  {filteredSuggestions.map((option, index) => (
                    <button
                      id={`${suggestionListId}-option-${index}`}
                      key={`${field.key}-${option.value}`}
                      type="button"
                      role="option"
                      aria-selected={index === activeSuggestionIndex}
                      className={`block w-full rounded-field px-3 py-2 text-left text-sm ${index === activeSuggestionIndex ? 'bg-base-300 text-base-content' : 'text-base-content hover:bg-base-200'}`}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => setSelectedSuggestion(option)}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}
