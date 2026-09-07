// 登录页级测试（计划 4）：表单渲染、提交传参、加载态、错误态。
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ThemeProvider } from '../context/ThemeContext';
import { LoginView } from './LoginView';
import { setViteDefineGlobals } from '../test/fetchMock';

beforeAll(() => {
  setViteDefineGlobals();
});

afterEach(() => {
  cleanup();
});

// BrandLogo 依赖主题上下文，页面级渲染需包 ThemeProvider（与 App 根一致）。
function renderView(ui: ReactElement) {
  return render(<ThemeProvider>{ui}</ThemeProvider>);
}

function fillForm() {
  fireEvent.change(screen.getByPlaceholderText('请输入用户名'), { target: { value: 'analyst01' } });
  fireEvent.change(screen.getByPlaceholderText('请输入密码'), { target: { value: 'S3cret-input' } });
}

describe('LoginView', () => {
  it('渲染标题、版本与双输入框', () => {
    renderView(<LoginView onLogin={async () => {}} loading={false} error="" />);
    expect(screen.getByText('互联网资产自动化收集系统')).toBeTruthy();
    expect(screen.getByText(/0\.0-test-page/)).toBeTruthy();
    expect(screen.getAllByDisplayValue('')).toHaveLength(2);
  });

  it('提交把用户名与密码原样传给 onLogin', async () => {
    const onLogin = vi.fn(async () => {});
    renderView(<LoginView onLogin={onLogin} loading={false} error="" />);
    fillForm();
    fireEvent.click(screen.getByRole('button', { name: '登录系统' }));
    expect(onLogin).toHaveBeenCalledWith('analyst01', 'S3cret-input');
  });

  it('loading 态禁用提交并切换文案（防重复登录请求）', () => {
    renderView(<LoginView onLogin={async () => {}} loading error="" />);
    const button = screen.getByRole('button');
    expect(button.hasAttribute('disabled')).toBe(true);
    expect(button.textContent).toBe('登录中...');
  });

  it('错误消息以独立错误条渲染', () => {
    renderView(<LoginView onLogin={async () => {}} loading={false} error="用户名或密码错误" />);
    expect(screen.getByText('用户名或密码错误')).toBeTruthy();
  });

  it('密码字段为 type=password（输入不回显明文语义）', () => {
    renderView(<LoginView onLogin={async () => {}} loading={false} error="" />);
    const pass = screen.getByPlaceholderText('请输入密码') as HTMLInputElement;
    expect(pass.type).toBe('password');
  });
});
