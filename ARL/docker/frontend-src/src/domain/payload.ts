import { deepClone } from './format';
import type {FlatPayloadField, JsonValue} from './types';

export function flattenPayloadFields(payload: JsonValue, parent = ''): FlatPayloadField[] {
  const fields: FlatPayloadField[] = [];
  Object.entries(payload || {}).forEach(([key, value]) => {
    const path = parent ? `${parent}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      fields.push(...flattenPayloadFields(value, path));
    } else {
      fields.push({
        path,
        value,
        depth: path.split('.').length - 1,
      });
    }
  });
  return fields;
}

export function updatePayloadValue(payload: JsonValue, path: string, value: any): JsonValue {
  const next = deepClone(payload || {});
  const parts = path.split('.');
  let cursor: any = next;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    if (!cursor[key] || typeof cursor[key] !== 'object' || Array.isArray(cursor[key])) {
      cursor[key] = {};
    }
    cursor = cursor[key];
  }
  cursor[parts[parts.length - 1]] = value;
  return next;
}

export function getPayloadValue(payload: JsonValue, path: string): any {
  if (!payload || !path) return undefined;
  const parts = path.split('.');
  let cursor: any = payload;
  for (const key of parts) {
    if (cursor === null || cursor === undefined || typeof cursor !== 'object') {
      return undefined;
    }
    cursor = cursor[key];
  }
  return cursor;
}
