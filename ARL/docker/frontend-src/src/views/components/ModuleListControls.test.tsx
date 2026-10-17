import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ModulePagination } from './ModulePagination';
import { ModuleSearchFields } from './ModuleSearchFields';

afterEach(cleanup);

describe('ModuleSearchFields', () => {
  it('renders configured inputs, updates values, and submits on Enter', () => {
    const onChange = vi.fn();
    const onEnter = vi.fn();
    render(
      <ModuleSearchFields
        moduleId="task"
        fields={[
          { key: 'name', label: '任务名', placeholder: '输入任务名' },
          {
            key: 'status',
            label: '状态',
            placeholder: '',
            inputType: 'select',
            options: [{ label: '全部', value: '' }, { label: '运行中', value: 'running' }],
          },
        ]}
        values={{ name: '', status: '' }}
        getOptions={(field) => field.options || []}
        getSuggestions={() => []}
        onChange={onChange}
        onEnter={onEnter}
      />,
    );

    const nameInput = screen.getByLabelText('任务名：');
    fireEvent.change(nameInput, { target: { value: 'nightly' } });
    fireEvent.keyDown(nameInput, { key: 'Enter' });
    fireEvent.change(screen.getByLabelText('状态：'), { target: { value: 'running' } });

    expect(onChange).toHaveBeenCalledWith('name', 'nightly');
    expect(onChange).toHaveBeenCalledWith('status', 'running');
    expect(onEnter).toHaveBeenCalledOnce();
  });
});

describe('ModulePagination', () => {
  it('sends bounded page and page-size changes to the list owner', () => {
    const onPageChange = vi.fn();
    const onPageSizeChange = vi.fn();
    render(
      <ModulePagination
        total={51}
        page={2}
        totalPages={3}
        pageOptions={[1, 2, 3]}
        size={20}
        onPageChange={onPageChange}
        onPageSizeChange={onPageSizeChange}
      />,
    );

    fireEvent.change(screen.getByLabelText('当前页'), { target: { value: '3' } });
    fireEvent.change(screen.getByLabelText('每页条数'), { target: { value: '50' } });
    fireEvent.click(screen.getByRole('button', { name: '上一页' }));

    expect(onPageChange.mock.calls.map(([page]) => page)).toEqual([3, 1]);
    expect(onPageSizeChange).toHaveBeenCalledWith(50);
    expect(screen.getByText('共 51 条，当前第 2/3 页')).toBeTruthy();
  });
});
