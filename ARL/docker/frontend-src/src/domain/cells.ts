import {
  extractFingerNames,
  formatCertHostCell,
  formatCertSummary,
  formatHeaderLines,
  formatTokenListText,
} from './finger';
import { formatDateTimeCell, getValueByPath, normalizeValue } from './format';
import {
  buildTaskOptionsSummary,
  buildTaskStatisticSummary,
  getTaskProgressPercent,
  getTaskStatusLabel,
  getTaskTypeLabel,
} from './task';
import { formatWihEndpointMetric } from './wih';

export function formatModuleCellValue(moduleId: string, column: string, row: any): string {
  const value = getValueByPath(row, column);

  if (moduleId === 'task') {
    if (column === 'target') {
      return formatTokenListText(value);
    }
    if (column === 'status') {
      return getTaskStatusLabel(value, { showRunningStage: true });
    }
    if (column === 'type') {
      return getTaskTypeLabel(value);
    }
    if (column === 'statistic_summary') {
      return buildTaskStatisticSummary(row);
    }
    if (column === 'options_summary') {
      return buildTaskOptionsSummary(row);
    }
    if (column === 'progress') {
      return `${getTaskProgressPercent(row)}%`;
    }
    if (column === 'start_time' || column === 'end_time') {
      return formatDateTimeCell(value);
    }
  }

  if (moduleId === 'task_schedule') {
    if (column === 'target') {
      return formatTokenListText(value);
    }
    if (column === 'schedule_type') {
      const mapping: Record<string, string> = {
        future_scan: '定时下发',
        recurrent_scan: '周期下发',
      };
      return mapping[String(value || '').toLowerCase()] || normalizeValue(value);
    }
    if (column === 'status') {
      const mapping: Record<string, string> = {
        scheduled: '待调度',
        stop: '已停止',
        done: '已完成',
        error: '异常',
      };
      return mapping[String(value || '').toLowerCase()] || normalizeValue(value);
    }
    if (column === 'time_config') {
      const scheduleType = String(row?.schedule_type || '').toLowerCase();
      if (scheduleType === 'future_scan') {
        return normalizeValue(row?.start_date || '-');
      }
      if (scheduleType === 'recurrent_scan') {
        return normalizeValue(row?.cron || '-');
      }
      return normalizeValue(row?.cron || row?.start_date || '-');
    }
  }

  if (moduleId === 'scheduler') {
    if (column === 'last_run_date' || column === 'next_run_date') {
      return formatDateTimeCell(value);
    }
  }

  if (moduleId === 'asset_scope') {
    if (column === 'scope') {
      return formatTokenListText(value);
    }
  }

  if (moduleId === 'github_scheduler') {
    if (column === 'status') {
      const mapping: Record<string, string> = {
        running: '运行中',
        stop: '停止',
      };
      return mapping[String(value || '').toLowerCase()] || normalizeValue(value);
    }
  }

  if (moduleId === 'github_task') {
    if (column === 'status') {
      return getTaskStatusLabel(value);
    }
    if (column === 'result_count') {
      const count = Number(row?.statistic?.github_result_cnt || 0);
      return String(Number.isFinite(count) ? count : 0);
    }
  }

  if ((moduleId === 'github_result' || moduleId === 'github_monitor_result') && column === 'commit_date') {
    return normalizeValue(value ?? row?.commit_time ?? row?.found_time);
  }

  // 子域名关联IP较长时按行展示，提升可读性。
  if ((moduleId === 'domain' || moduleId === 'asset_domain') && column === 'ips') {
    return formatTokenListText(value);
  }

  if ((moduleId === 'domain' || moduleId === 'asset_domain') && column === 'source') {
    const sourceList = [
      ...(Array.isArray(row?.sources) ? row.sources : [row?.sources]),
      value,
    ]
      .flatMap((item) => String(item ?? '').split(','))
      .map((item) => item.trim())
      .filter((item) => item && item !== '-');
    return Array.from(new Set(sourceList)).join('\n') || '-';
  }

  // IP模块的多值端口/域名按行展示，避免单行过长。
  if ((moduleId === 'ip' || moduleId === 'asset_ip') && (column === 'port_info.port_id' || column === 'domain')) {
    return formatTokenListText(value);
  }

  if (moduleId === 'ip') {
    if (column === 'geo_summary') {
      const country = normalizeValue(row?.geo_city?.country_name);
      const region = normalizeValue(row?.geo_city?.region_name);
      const city = normalizeValue(row?.geo_city?.city_name);
      const composed = [country, region, city].filter((item) => item && item !== '-').join(' / ');
      return composed || '-';
    }
    if (column === 'asn_summary') {
      const asn = normalizeValue(row?.geo_asn?.number);
      const organization = normalizeValue(row?.geo_asn?.organization);
      if (asn !== '-' && organization !== '-') return `${asn} ${organization}`;
      if (asn !== '-') return asn;
      return organization;
    }
  }

  if (moduleId === 'cert') {
    if (column === 'host') {
      return formatCertHostCell(row);
    }
    if (column === 'cert_summary') {
      return formatCertSummary(row);
    }
  }

  if (moduleId === 'service' && column === 'ip_port') {
    const infoList = Array.isArray(row?.service_info)
      ? row.service_info
      : (row?.service_info && typeof row.service_info === 'object' ? [row.service_info] : []);

    const ipPortList = infoList
      .map((item: any) => {
        const rawIp = item?.ip;
        const rawPort = item?.port_id;
        const ip = rawIp === null || rawIp === undefined ? '' : String(rawIp).trim();
        const port = rawPort === null || rawPort === undefined ? '' : String(rawPort).trim();
        if (!ip && !port) return '';
        if (!port) return ip;
        if (!ip) return port;
        return `${ip}:${port}`;
      })
      .filter((item: string) => item && item !== '-');

    if (ipPortList.length === 0) return '-';
    return Array.from(new Set(ipPortList)).join('\n');
  }

  if (moduleId === 'service' && column === 'service_info.product') {
    const infoList = Array.isArray(row?.service_info)
      ? row.service_info
      : (row?.service_info && typeof row.service_info === 'object' ? [row.service_info] : []);

    const productList = infoList
      .flatMap((item: any) => {
        const productCandidates = [item?.product, item?.service_product, item?.serviceProduct];
        return productCandidates
          .filter((raw) => raw !== null && raw !== undefined)
          .flatMap((raw) =>
            String(raw)
              .split(/[\r\n,]+/)
              .map((part) => part.trim())
          );
      })
      .filter((item: string) => item && item !== '-');

    // 未开启服务识别(-sV)或服务指纹不足时，产品信息可能为空，这里给出明确提示。
    if (productList.length === 0) return '未识别';
    return Array.from(new Set(productList)).join(', ');
  }

  if (moduleId === 'vuln' && column === 'credential') {
    const verifyData = normalizeValue(row?.verify_data);
    if (verifyData !== '-') return verifyData;
    return normalizeValue(row?.verify_obj);
  }


  if (moduleId === 'nuclei_result' && column === 'scanner_type') {
    const scannerType = String(value || '').trim().toLowerCase();
    if (scannerType === 'nuclei') return 'Nuclei';
    if (scannerType === 'afrog') return 'afrog';
  }

  if (moduleId === 'fileleak' && column === 'source') {
    const sourceText = String(value || '').trim().toLowerCase();
    const sourceMap: Record<string, string> = {
      '': '字典爆破',
      dict_brute: '字典爆破',
      dictionary_brute: '字典爆破',
      brute: '字典爆破',
      wih_url_probe: 'wih_url_probe',
    };
    return sourceMap[sourceText] || normalizeValue(value);
  }

  if (moduleId === 'wih_endpoint') {
    if (column === 'method') {
      return String(value || '').trim().toUpperCase() || '-';
    }
    if (column === 'status_code' || column === 'response_size') {
      return formatWihEndpointMetric(row, column);
    }
    if (column === 'detail_action') {
      return '查看详情';
    }
  }


  if (moduleId === 'asset_scope' && column === 'scope') {
    return formatTokenListText(value);
  }

  if ((moduleId === 'asset_site' || moduleId === 'site') && column === 'headers') {
    return formatHeaderLines(value);
  }

  if ((moduleId === 'asset_site' || moduleId === 'site') && column === 'finger') {
    const fingerNames = extractFingerNames(value);
    if (fingerNames.length > 0) return fingerNames.join('\n');
  }

  return normalizeValue(value);
}
