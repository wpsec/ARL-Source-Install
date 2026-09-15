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
  // 只复制从根到目标字段的对象，避免批量 POC 配置变更时序列化整个表单。
  const sourcePayload = payload || {};
  const next = { ...sourcePayload };
  const parts = path.split('.');
  let cursor: any = next;
  let source: any = sourcePayload;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    const sourceValue = source?.[key];
    const nextValue = sourceValue && typeof sourceValue === 'object' && !Array.isArray(sourceValue)
      ? { ...sourceValue }
      : {};
    cursor[key] = nextValue;
    cursor = nextValue;
    source = sourceValue;
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
