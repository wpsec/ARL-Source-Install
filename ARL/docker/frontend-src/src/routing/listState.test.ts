import { describe, expect, it } from 'vitest';
import { getModuleById } from '../config/modules';
import { buildModuleListSearch, hasModuleListUrlState, parseModuleListUrlState } from './listState';

describe('模块列表 URL 状态', () => {
  const taskModule = getModuleById('task');

  it('读取页码、排序及模块搜索字段', () => {
    expect(parseModuleListUrlState('?page=3&size=20&order=start_time&status=running&target=example.com', taskModule, 50)).toEqual({
      page: 3,
      size: 20,
      order: 'start_time',
      quickFilter: '',
      searchForm: expect.objectContaining({ status: 'running', target: 'example.com' }),
    });
  });

  it('只写非默认值并保留路由外部筛选', () => {
    const state = {
      page: 2,
      size: 20,
      order: '-_id',
      quickFilter: '',
      searchForm: { status: 'running', target: '' },
    };

    const result = buildModuleListSearch('?x.scope_id=scope-1&page=1', taskModule, state, 50);
    const params = new URLSearchParams(result);
    expect(params.get('x.scope_id')).toBe('scope-1');
    expect(params.get('page')).toBe('2');
    expect(params.get('size')).toBe('20');
    expect(params.has('order')).toBe(false);
    expect(params.get('status')).toBe('running');
    expect(params.has('target')).toBe(false);
    expect(hasModuleListUrlState(result, taskModule)).toBe(true);
  });
});
