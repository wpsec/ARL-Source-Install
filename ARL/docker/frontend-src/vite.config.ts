import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  const versionPath = path.resolve(__dirname, '../../version.txt');
  let arlVersion = 'unknown';
  try {
    arlVersion = fs.readFileSync(versionPath, 'utf-8').trim() || 'unknown';
  } catch {
    arlVersion = 'unknown';
  }
  return {
    plugins: [react(), tailwindcss()],
    // 仅注入版本号常量。禁止把任何环境变量 define 进浏览器 bundle
    // （历史脚手架曾注入 GEMINI_API_KEY，构建环境存在该变量即泄露，AI 能力全部走后端 /api）。
    define: {
      __ARL_VERSION__: JSON.stringify(arlVersion),
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: true,
    },
  };
});
