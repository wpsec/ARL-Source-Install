import { normalizeValue, truncateText } from './format';

export function buildCidrPrefix(value: any): string {
  const text = String(value ?? '').trim();
  if (!text || text === '-') return '';
  const cidrMatch = text.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?:\/\d{1,2})?$/);
  if (cidrMatch?.[1]) return `${cidrMatch[1]}.`;
  const prefixMatch = text.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.?$/);
  if (prefixMatch?.[1]) return `${prefixMatch[1]}.`;
  return '';
}

export function parseListFromString(text: string): string[] {
  const normalized = text.trim();
  if (!normalized) return [];

  const tryParseJson = (): string[] => {
    if (!(normalized.startsWith('[') && normalized.endsWith(']'))) return [];
    try {
      const parsed = JSON.parse(normalized);
      if (!Array.isArray(parsed)) return [];
      return parsed
        .map((item) => String(item ?? '').trim())
        .filter((item) => item);
    } catch {
      return [];
    }
  };

  const jsonTokens = tryParseJson();
  if (jsonTokens.length > 0) return jsonTokens;

  const pyListMatch = normalized.match(/^\[(.*)\]$/);
  if (pyListMatch) {
    const body = pyListMatch[1].trim();
    if (!body) return [];
    return body
      .split(/\s*,\s*/)
      .map((item) => item.trim().replace(/^['"]|['"]$/g, ''))
      .filter((item) => item);
  }

  return normalized
    .split(/[,\uFF0C;\uFF1B\r\n\t\s]+/)
    .map((item) => item.trim())
    .filter((item) => item);
}

export function parseFingerListFromString(text: string): string[] {
  const normalized = text.trim();
  if (!normalized) return [];

  const tryParseJson = (): string[] => {
    if (!((normalized.startsWith('[') && normalized.endsWith(']')) || (normalized.startsWith('{') && normalized.endsWith('}')))) {
      return [];
    }
    try {
      const parsed = JSON.parse(normalized);
      if (Array.isArray(parsed)) {
        return parsed
          .map((item) => String(item ?? '').trim())
          .filter((item) => item);
      }
      if (parsed && typeof parsed === 'object') {
        const name = String((parsed as Record<string, any>).name || (parsed as Record<string, any>).cms || '').trim();
        return name ? [name] : [];
      }
    } catch {
      return [];
    }
    return [];
  };

  const jsonTokens = tryParseJson();
  if (jsonTokens.length > 0) return jsonTokens;

  const pyListMatch = normalized.match(/^\[(.*)\]$/);
  if (pyListMatch) {
    const body = pyListMatch[1].trim();
    if (!body) return [];
    return body
      .split(/\s*,\s*/)
      .map((item) => item.trim().replace(/^['"]|['"]$/g, ''))
      .filter((item) => item);
  }

  return normalized
    .split(/[,\uFF0C;\uFF1B\r\n]+/)
    .map((item) => item.trim())
    .filter((item) => item);
}

export function extractFingerNames(value: any): string[] {
  if (value === null || value === undefined) return [];

  const addTokens = (bucket: string[], raw: any) => {
    if (raw === null || raw === undefined) return;
    if (typeof raw === 'string') {
      bucket.push(...parseFingerListFromString(raw));
      return;
    }
    if (Array.isArray(raw)) {
      raw.forEach((item) => addTokens(bucket, item));
      return;
    }
    if (typeof raw === 'object') {
      const obj = raw as Record<string, any>;
      const name = String(obj.name || obj.cms || '').trim();
      if (name) {
        bucket.push(name);
      } else {
        const fallback = String(raw).trim();
        if (fallback && fallback !== '[object Object]') bucket.push(fallback);
      }
      return;
    }
    const text = String(raw).trim();
    if (text) bucket.push(text);
  };

  const tokens: string[] = [];
  addTokens(tokens, value);
  return Array.from(new Set(tokens.filter((item) => item && item !== '-')));
}

export function formatTokenListText(value: any): string {
  if (value === null || value === undefined) return '-';
  if (Array.isArray(value)) {
    const tokens = value
      .flatMap((item) => parseListFromString(String(item || '')))
      .filter((item) => item);
    return tokens.length > 0 ? tokens.join('\n') : '-';
  }
  const text = String(value).trim();
  if (!text) return '-';
  const tokens = parseListFromString(text);
  if (tokens.length > 1) return tokens.join('\n');
  return tokens[0] || text;
}

export function formatHeaderLines(value: any): string {
  if (value === null || value === undefined) return '-';

  let source = value;
  if (typeof source === 'string') {
    const text = source.trim();
    if (!text) return '-';
    try {
      source = JSON.parse(text);
    } catch {
      if (text.includes('\n')) {
        return text
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line)
          .slice(0, 12)
          .join('\n');
      }
      return truncateText(text, 360);
    }
  }

  const lines: string[] = [];
  const appendLine = (key: string, item: any) => {
    let itemText = '';
    if (item === null || item === undefined) {
      itemText = '';
    } else if (Array.isArray(item)) {
      itemText = item.map((part) => String(part ?? '')).filter((part) => part).join(', ');
    } else if (typeof item === 'object') {
      itemText = JSON.stringify(item);
    } else {
      itemText = String(item);
    }
    const normalizedValue = truncateText(itemText, 240);
    lines.push(key ? `${key}: ${normalizedValue}` : normalizedValue);
  };

  if (Array.isArray(source)) {
    source.forEach((item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        Object.entries(item).forEach(([key, subItem]) => appendLine(key, subItem));
      } else {
        appendLine('', item);
      }
    });
  } else if (source && typeof source === 'object') {
    Object.entries(source).forEach(([key, item]) => appendLine(key, item));
  } else {
    return truncateText(String(source), 360);
  }

  if (lines.length === 0) return '-';
  if (lines.length > 12) {
    return `${lines.slice(0, 12).join('\n')}\n...`;
  }
  return lines.join('\n');
}

export function formatCertSummary(row: any): string {
  const cert = row?.cert && typeof row.cert === 'object' ? row.cert : {};
  const sslSecurity = cert?.ssl_security && typeof cert.ssl_security === 'object' ? cert.ssl_security : {};
  const toText = (value: any, max = 420): string => {
    if (value === null || value === undefined) return '-';
    if (Array.isArray(value)) {
      const text = value.map((item) => String(item ?? '')).filter((item) => item).join(', ');
      return truncateText(text || '-', max);
    }
    if (typeof value === 'object') {
      return truncateText(JSON.stringify(value), max);
    }
    return truncateText(String(value), max);
  };
  const subjectDn = toText(cert?.subject_dn);
  const issuerDn = toText(cert?.issuer_dn);
  const san = toText(cert?.extensions?.subjectAltName, 720);
  const serialNumber = toText(cert?.serial_number);
  const validityStart = toText(cert?.validity?.start);
  const validityEnd = toText(cert?.validity?.end);
  const sha256 = toText(cert?.fingerprint?.sha256);
  const sha1 = toText(cert?.fingerprint?.sha1);
  const md5 = toText(cert?.fingerprint?.md5);
  const protocolNamesFromItems = Array.isArray(sslSecurity?.protocols)
    ? sslSecurity.protocols
      .map((item: any) => (item && typeof item === 'object' ? String(item.name || '').trim() : String(item || '').trim()))
      .filter((item: string) => item)
    : [];
  const protocolNamesFromList = Array.isArray(sslSecurity?.protocol_names)
    ? sslSecurity.protocol_names.map((item: any) => String(item || '').trim()).filter((item: string) => item)
    : [];
  const protocolNames = Array.from(new Set([...protocolNamesFromItems, ...protocolNamesFromList]));
  const protocolText = protocolNames.length > 0 ? protocolNames.join(', ') : '-';

  const leastStrength = toText(sslSecurity?.least_strength);
  const ecdheCountRaw = Number(sslSecurity?.ecdhe_count);
  const ecdheCount = Number.isFinite(ecdheCountRaw) ? String(ecdheCountRaw) : '-';

  const cipherItems = Array.isArray(sslSecurity?.cipher_suites)
    ? sslSecurity.cipher_suites.filter((item: any) => item && typeof item === 'object')
    : [];
  const cipherPreviewLines = cipherItems.slice(0, 16).map((item: any) => {
    const protocol = String(item.protocol || '').trim();
    const name = String(item.name || '').trim();
    const strength = String(item.strength || '').trim().toUpperCase();
    if (!name) return '';
    let line = name;
    if (protocol) line = `[${protocol}] ${line}`;
    if (strength) line = `${line} (${strength})`;
    return line;
  }).filter((item: string) => item);
  if (cipherItems.length > 16) {
    cipherPreviewLines.push(`... 共 ${cipherItems.length} 条`);
  }

  const summaryLines = [
    '基本信息',
    `主题名称: ${subjectDn}`,
    `签发者名称: ${issuerDn}`,
    `使用者备用名称: ${san}`,
    `序列号: ${serialNumber}`,
    `时间: ${validityStart} 至 ${validityEnd}`,
    '协议支持',
    `支持协议: ${protocolText}`,
    `最弱加密强度: ${leastStrength}`,
    `ECDHE套件数: ${ecdheCount}`,
    '加密套件',
    `已启用套件: ${cipherPreviewLines.length > 0 ? '' : '-'}`,
    '指纹',
    `SHA-256: ${sha256}`,
    `SHA-1: ${sha1}`,
    `MD5: ${md5}`,
  ];

  if (cipherPreviewLines.length > 0) {
    cipherPreviewLines.forEach((line, index) => {
      summaryLines.push(`  ${index + 1}. ${line}`);
    });
  }

  return summaryLines.join('\n');
}

export function formatCertHostCell(row: any): string {
  const ip = normalizeValue(row?.ip);
  const port = normalizeValue(row?.port);
  const endpoint = ip === '-' && port === '-' ? '-' : (port === '-' ? ip : `${ip}:${port}`);
  const scanMode = String(row?.scan_mode || '').trim().toLowerCase();

  const domainCandidates: string[] = [];
  const sniDomain = String(row?.sni_domain || '').trim();
  if (sniDomain) {
    domainCandidates.push(sniDomain);
  }
  const primaryDomain = String(row?.domain || '').trim();
  if (primaryDomain) {
    domainCandidates.push(primaryDomain);
  }
  if (scanMode === 'sni') {
    const domainList = Array.isArray(row?.domains) ? row.domains : [];
    domainList.forEach((item: any) => {
      const text = String(item || '').trim();
      if (text) domainCandidates.push(text);
    });
  }
  const uniqueDomains = Array.from(new Set(domainCandidates));
  const domain = uniqueDomains.length > 0 ? uniqueDomains[0] : '-';

  // 证书列表优先展示域名身份，再附带IP端点，避免“看起来只按IP查证书”的误解。
  if (domain !== '-' && endpoint !== '-') return `${domain} -> ${endpoint}`;
  if (domain !== '-') return domain;
  return endpoint;
}
