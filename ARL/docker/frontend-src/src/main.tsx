import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';
import App from './App.tsx';
import './index.css';

// 读侧缓存单一实例（docs/04 数据层规则）：staleTime 由调用点按模块语义设定，
// 写路径与轮询协议保持现状，本 client 只做去重与短期缓存。
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 0,
      refetchOnWindowFocus: false,
    },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
