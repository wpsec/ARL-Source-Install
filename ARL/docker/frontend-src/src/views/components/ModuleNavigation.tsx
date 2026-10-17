import { ChevronLeft } from 'lucide-react';
import { TASK_DETAIL_TABS } from '../../config/modules';
import type { JsonValue, OpenModuleHandler } from '../../domain/types';
import {
  CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS,
  CONSOLE_PRIMARY_BUTTON_CLASS,
} from '../../ui/classes';

const ASSET_GROUP_MODULES = [
  { id: 'scheduler', label: '资产监控' },
  { id: 'asset_scope', label: '资产分组' },
  { id: 'asset_site', label: '组站点' },
  { id: 'asset_domain', label: '组子域名' },
  { id: 'asset_ip', label: '组IP' },
  { id: 'asset_wih', label: '组WIH' },
];

const TASK_ASSET_MODULE_IDS = new Set([
  'site', 'domain', 'ip', 'cert', 'service', 'fileleak', 'url', 'vuln',
  'nuclei_result', 'stat_finger', 'wih', 'wih_endpoint', 'waf_host',
]);

export function ModuleNavigation({
  moduleId,
  hasExternalFilters,
  externalFilters,
  taskDetailCounts,
  taskDetailCountLoading,
  onOpenModule,
}: {
  moduleId: string;
  hasExternalFilters: boolean;
  externalFilters: JsonValue;
  taskDetailCounts: Record<string, number | undefined>;
  taskDetailCountLoading: boolean;
  onOpenModule: OpenModuleHandler;
}) {
  if (ASSET_GROUP_MODULES.some((item) => item.id === moduleId)) {
    return (
      <nav className="flex min-w-0 flex-wrap gap-2" aria-label="资产监控与分组页面">
        {ASSET_GROUP_MODULES.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onOpenModule(item.id)}
            className={moduleId === item.id ? CONSOLE_PRIMARY_BUTTON_CLASS : CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS}
            aria-current={moduleId === item.id ? 'page' : undefined}
          >
            {item.label}
          </button>
        ))}
      </nav>
    );
  }

  if (!TASK_ASSET_MODULE_IDS.has(moduleId)) return null;

  return (
    <nav className="flex min-w-0 flex-wrap gap-2" aria-label="资产数据与任务详情">
      {hasExternalFilters ? (
        <button
          type="button"
          onClick={() => onOpenModule('task', undefined, { resetScroll: true })}
          className={`${CONSOLE_PRIMARY_BUTTON_CLASS} gap-1.5`}
          title="返回任务管理"
        >
          <ChevronLeft className="h-4 w-4" />
          返回任务管理
        </button>
      ) : null}
      {TASK_DETAIL_TABS.map((tab) => {
        const count = taskDetailCounts[tab.id];
        const countLabel = typeof count === 'number' ? count : taskDetailCountLoading ? '…' : 0;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onOpenModule(tab.id, hasExternalFilters ? externalFilters : undefined)}
            className={moduleId === tab.id ? CONSOLE_PRIMARY_BUTTON_CLASS : CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS}
            aria-current={moduleId === tab.id ? 'page' : undefined}
          >
            {tab.label} · {countLabel}
          </button>
        );
      })}
    </nav>
  );
}
