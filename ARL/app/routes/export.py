#coding: utf-8
"""
任务报告导出模块

功能说明：
- 导出任务扫描结果为Excel报告
- 包含完整的统计分析和数据汇总
- 提供可视化的资产信息展示

报告内容：
1. 任务概览：任务名称、目标、时间、配置等
2. IP统计：IP总数、端口分布、服务分布
3. 域名统计：域名总数、类型分布
4. 站点统计：站点总数、状态码分布、指纹分布
5. 详细数据：完整的IP、域名、站点、服务列表

导出格式：
- Excel (.xlsx) 文件
- 多个工作表分类展示数据
- 包含样式和格式化
"""

from flask import  make_response, request
from flask_restx import Resource, Namespace
from openpyxl import Workbook
from bson import ObjectId
import re
from datetime import datetime
from collections import Counter
from openpyxl.writer.excel import save_virtual_workbook
from openpyxl.styles import Font, Color, PatternFill, Alignment, Border, Side
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.utils import get_column_letter
from app.utils import get_logger, auth
from app import utils
from urllib.parse import quote

ns = Namespace('export', description="任务报告导出接口")

logger = get_logger()


def sanitize_excel_value(value):
    """
    清洗Excel单元格值，避免非法字符导致导出失败

    说明：
    - 处理 None/bytes/复杂对象类型，统一转换为字符串
    - 过滤 openpyxl 不支持的控制字符
    - 截断超长内容（Excel单元格上限 32767）
    """
    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")

    if not isinstance(value, str):
        value = str(value)

    value = ILLEGAL_CHARACTERS_RE.sub("", value)
    return value[:32767]


def extract_finger_names(finger_data):
    """
    提取指纹名称列表，兼容 dict/list/str/None 等多种数据格式
    """
    if not finger_data:
        return ""

    if not isinstance(finger_data, list):
        return sanitize_excel_value(finger_data)

    names = []
    for item in finger_data:
        if isinstance(item, dict):
            names.append(sanitize_excel_value(item.get("name", "")))
        else:
            names.append(sanitize_excel_value(item))
    return ",".join([name for name in names if name])


def _beautify_sheet(ws, center_cols=None):
    """
    统一增强工作表可读性：
    - 冻结首行
    - 表头高亮
    - 自动筛选
    - 斑马纹 + 边框 + 自动换行
    """
    max_row = ws.max_row
    max_col = ws.max_column
    if max_row <= 0 or max_col <= 0:
        return

    center_cols = set(center_cols or [])

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = "A1:{}{}".format(get_column_letter(max_col), max_row)

    header_fill = PatternFill(fill_type="solid", fgColor="2F75B5")
    zebra_fill = PatternFill(fill_type="solid", fgColor="F6FAFF")
    thin_side = Side(style="thin", color="D9E2F3")
    thin_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)
    body_font = Font(name="Consolas", color="111111")

    ws.row_dimensions[1].height = 24
    for col in range(1, max_col + 1):
        cell = ws.cell(row=1, column=col)
        cell.font = Font(name="Consolas", color="FFFFFF", bold=True)
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = thin_border

    for row in range(2, max_row + 1):
        use_zebra = row % 2 == 0
        for col in range(1, max_col + 1):
            cell = ws.cell(row=row, column=col)
            cell.font = body_font
            if use_zebra:
                cell.fill = zebra_fill
            cell.border = thin_border
            if col in center_cols:
                cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            else:
                cell.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)


def set_sheet_style(ws):
    """
    通用工作表样式（默认左对齐）
    """
    _beautify_sheet(ws)


def beautify_cert_sheet(ws):
    """
    SSL 证书工作表样式（保留部分字段居中）
    """
    _beautify_sheet(ws, center_cols={5, 6, 7, 8, 9, 10})


def as_list(value):
    """
    将值标准化为列表，兼容 None/单值/列表
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def calc_port_service_product_statist_from_ip_items(ip_items):
    """
    基于合并后的IP数据计算资产统计（与单任务统计口径保持一致）
    """
    total = 0
    port_info_list = []
    for item in ip_items:
        port_info = item.get("port_info", [])
        if not port_info:
            continue
        port_info_list.extend(port_info)
        total += len(port_info)

    counter = Counter([info.get("port_id") for info in port_info_list if info.get("port_id") is not None])
    top_20 = counter.most_common(20)
    port_percent_list = []
    for port_id, amount in top_20:
        percent = "{:.2f}%".format((amount * 100.0) / total) if total else "0.00%"
        port_percent_list.append({
            "port_id": port_id,
            "amount": amount,
            "percent": percent
        })

    service_name_list = []
    for info in port_info_list:
        if not info.get("product"):
            continue
        if info.get("product") or info.get("version"):
            service_name = info.get("service_name", "")
            if service_name == "https-alt":
                service_name = "https"
            service_name_list.append(service_name)

    service_top_20 = Counter(service_name_list).most_common(20)
    service_percent_list = []
    for service_name, amount in service_top_20:
        percent = "{:.2f}%".format((amount * 100.0) / len(service_name_list)) if service_name_list else "0.00%"
        service_percent_list.append({
            "service_name": service_name,
            "amount": amount,
            "percent": percent
        })

    product_name_list = []
    for info in port_info_list:
        product = info.get("product")
        if not product:
            continue
        product = sanitize_excel_value(product).strip()
        if product and "**" not in product:
            product_name_list.append(product)

    product_top_20 = Counter(product_name_list).most_common(20)
    product_percent_list = []
    for product, amount in product_top_20:
        percent = "{:.2f}%".format((amount * 100.0) / len(product_name_list)) if product_name_list else "0.00%"
        product_percent_list.append({
            "product": product,
            "amount": amount,
            "percent": percent
        })

    return {
        "port_total": total,
        "port_percent_list": port_percent_list,
        "service_total": len(service_name_list),
        "service_percent_list": service_percent_list,
        "product_total": len(product_name_list),
        "product_percent_list": product_percent_list
    }


@ns.route('/<string:task_id>')
class ARLExport(Resource):
    """任务报告导出接口"""
    
    @auth
    def get(self, task_id):
        """
        导出任务扫描报告为Excel文件
        
        参数：
            task_id: 任务ID
        
        返回：
            Excel文件下载
        
        说明：
        - 生成包含完整扫描结果的Excel报告
        - 文件名：ARL资产导出报告_目标.xlsx
        - 包含多个工作表：
          * 任务概览
          * IP列表及端口服务
          * 域名列表及DNS记录
          * 站点列表及指纹
          * 统计分析（端口Top20、服务Top20等）
        - 适合报告归档和资产分析
        """
        task_data = get_task_data(task_id)
        if not task_data:
            return "not found"

        # 生成文件名（截取目标前20个字符）
        domain = task_data["target"].replace("/", "_")[:20]
        filename = "ARL资产导出报告_{}.xlsx".format(domain)

        # 生成Excel数据
        excel_data = export_arl(task_id)
        response = make_response(excel_data)
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers["Content-Disposition"] = "attachment; filename={}".format(quote(filename))

        return response



@ns.route('/batch')
class ARLBatchExcel(Resource):
    """批量合并导出接口 - 支持POST请求接收多个任务ID"""
    
    @auth
    def post(self):
        """
        批量导出多个任务并合并成一个Excel文件
        
        请求体：
            {
                "task_ids": ["任务ID1", "任务ID2", ...]
            }
        
        返回：
            合并后的Excel文件下载
        
        说明：
        - 接收多个任务ID列表
        - 合并所有任务的扫描数据（IP、域名、站点等）
        - 自动去重
        - 生成统一的整合Excel报告
        - 文件名：ARL批量导出报告_任务名.xlsx
        """
        try:
            data = request.get_json(silent=True)
            if not data:
                return {"error": "请求体为空"}, 400
                
            task_ids = data.get("task_ids", [])
            
            if not task_ids or not isinstance(task_ids, list):
                return {"error": "task_ids 必须是非空的列表"}, 400
            
            # 获取任务名（从第一个任务）
            first_task = get_task_data(task_ids[0])
            if not first_task:
                return {"error": "任务不存在"}, 404
            
            task_name = first_task.get("name", "未知")
            filename = "ARL批量导出报告_{}.xlsx".format(task_name[:20])
            
            # 生成整合Excel
            excel_data = export_merge_tasks(task_ids)
            
            response = make_response(excel_data)
            response.headers['Content-Type'] = 'application/octet-stream'
            response.headers["Content-Disposition"] = "attachment; filename={}".format(quote(filename))
            
            return response
        except Exception as e:
            logger.exception("批量导出失败: {}".format(str(e)))
            return {"error": "导出失败: {}".format(str(e))}, 500






def get_task_data(task_id):
    """
    获取任务数据
    
    参数：
        task_id: 任务ID
    
    返回：
        任务数据字典或None
    """
    try:
        task_data = utils.conn_db('task').find_one({'_id': ObjectId(task_id)})
        return task_data
    except Exception as e:
        pass


def get_ip_data(task_id):
    """
    获取任务的IP数据
    
    参数：
        task_id: 任务ID
    
    返回：
        IP数据游标
    """
    data =  utils.conn_db('ip').find({'task_id': task_id})
    return data


def get_site_data(task_id):
    """
    获取任务的站点数据
    
    参数：
        task_id: 任务ID
    
    返回：
        站点数据游标
    """
    data = utils.conn_db('site').find({'task_id': task_id})
    return data


def get_domain_data(task_id):
    """
    获取任务的域名数据
    
    参数：
        task_id: 任务ID
    
    返回：
        域名数据游标
    """
    data = utils.conn_db('domain').find({'task_id': task_id})
    return data


def get_url_data(task_id):
    """
    获取任务的 URL 信息数据。
    """
    return utils.conn_db('url').find({'task_id': task_id})


def get_fileleak_data(task_id):
    """
    获取任务的目录扫描（文件泄露）数据。
    """
    return utils.conn_db('fileleak').find({'task_id': task_id})


def get_wih_data(task_id):
    """
    获取任务的 WIH 数据。
    """
    return utils.conn_db('wih').find({'task_id': task_id})


def _normalize_task_id_list(task_ids):
    """
    规范化任务ID列表，兼容 str/list/tuple/set 输入。
    """
    if isinstance(task_ids, str):
        raw_items = [task_ids]
    elif isinstance(task_ids, (list, tuple, set)):
        raw_items = list(task_ids)
    else:
        raw_items = []

    result = []
    for item in raw_items:
        task_id = sanitize_excel_value(item).strip()
        if task_id and task_id not in result:
            result.append(task_id)
    return result


def get_service_data(task_ids):
    """
    获取任务的系统服务数据（service 集合）。
    """
    task_id_list = _normalize_task_id_list(task_ids)
    if not task_id_list:
        return []

    if len(task_id_list) == 1:
        query = {"task_id": task_id_list[0]}
    else:
        query = {"task_id": {"$in": task_id_list}}
    return utils.conn_db('service').find(query)


def _build_service_rows(task_ids, fallback_ip_items=None):
    """
    生成系统服务导出行，优先与页面一致使用 service 集合；
    若 service 集合为空，则回退到 ip.port_info。
    """
    rows = []
    task_id_list = _normalize_task_id_list(task_ids)
    expected_task_ids = set(task_id_list)
    service_hit_task_ids = set()

    for service_item in get_service_data(task_id_list):
        if not isinstance(service_item, dict):
            continue
        service_task_id = sanitize_excel_value(service_item.get("task_id", "")).strip()
        if service_task_id:
            service_hit_task_ids.add(service_task_id)
        service_name = service_item.get("service_name", "")
        for service_info in as_list(service_item.get("service_info", [])):
            if not isinstance(service_info, dict):
                continue
            rows.append([
                service_info.get("ip", ""),
                service_info.get("port_id", ""),
                service_name or service_info.get("service_name", ""),
                service_info.get("product", ""),
                service_info.get("version", ""),
            ])

    missing_task_ids = set()
    if expected_task_ids:
        missing_task_ids = expected_task_ids - service_hit_task_ids
        if rows and not missing_task_ids:
            return rows
    elif rows:
        return rows

    for item in fallback_ip_items or []:
        if not isinstance(item, dict):
            continue

        item_task_id = sanitize_excel_value(item.get("task_id", "")).strip()
        if expected_task_ids:
            if item_task_id:
                if item_task_id not in missing_task_ids:
                    continue
            elif rows and missing_task_ids:
                # 无 task_id 的回退数据无法确定归属，避免与已命中的服务数据重复
                continue

        ip = item.get("ip", "")
        for port_info in as_list(item.get("port_info", [])):
            if not isinstance(port_info, dict):
                continue
            rows.append([
                ip,
                port_info.get("port_id", ""),
                port_info.get("service_name", ""),
                port_info.get("product", ""),
                port_info.get("version", ""),
            ])

    return rows


def get_vuln_data(task_id):
    """
    获取任务的漏洞数据（nPoc/风险巡航等）
    """
    return utils.conn_db('vuln').find({'task_id': task_id})


def get_nuclei_result_data(task_id):
    """
    获取任务的 nuclei 漏洞结果
    """
    return utils.conn_db('nuclei_result').find({'task_id': task_id})


def get_cert_data(task_id):
    """
    获取任务的 SSL 证书结果
    """
    return utils.conn_db('cert').find({'task_id': task_id})


def _extract_url_rows(task_ids):
    """
    汇总 URL 信息导出行，按关键字段去重。
    """
    task_id_list = _normalize_task_id_list(task_ids)
    rows = []
    dedup_keys = set()
    for task_id in task_id_list:
        for item in get_url_data(task_id):
            row = [
                sanitize_excel_value(item.get("url", "")),
                sanitize_excel_value(item.get("site", "")),
                sanitize_excel_value(item.get("title", "")),
                sanitize_excel_value(item.get("status_code", "")),
                sanitize_excel_value(item.get("content_length", "")),
                sanitize_excel_value(item.get("source", "")),
            ]
            key = tuple(row)
            if key in dedup_keys:
                continue
            dedup_keys.add(key)
            rows.append(row)
    return rows


def _extract_fileleak_rows(task_ids):
    """
    汇总目录扫描（文件泄露）导出行，按 URL 去重。
    """
    task_id_list = _normalize_task_id_list(task_ids)
    rows = []
    dedup_urls = set()
    for task_id in task_id_list:
        for item in get_fileleak_data(task_id):
            url = sanitize_excel_value(item.get("url", "")).strip()
            if not url or url in dedup_urls:
                continue
            dedup_urls.add(url)
            rows.append(
                [
                    url,
                    sanitize_excel_value(item.get("site", "")),
                    sanitize_excel_value(item.get("title", "")),
                    sanitize_excel_value(item.get("status_code", "")),
                    sanitize_excel_value(item.get("content_length", "")),
                ]
            )
    return rows


def _extract_wih_rows(task_ids):
    """
    汇总 WIH 导出行，按 record_type+content+source+site 去重。
    """
    task_id_list = _normalize_task_id_list(task_ids)
    rows = []
    dedup_keys = set()
    for task_id in task_id_list:
        for item in get_wih_data(task_id):
            row = [
                sanitize_excel_value(item.get("record_type", "")),
                sanitize_excel_value(item.get("content", "")),
                sanitize_excel_value(item.get("source", "")),
                sanitize_excel_value(item.get("site", "")),
            ]
            key = tuple(row)
            if key in dedup_keys:
                continue
            dedup_keys.add(key)
            rows.append(row)
    return rows


def _build_url_sheet(wb, task_ids):
    """
    在导出工作簿中新增 URL 信息工作表。
    """
    ws = wb.create_sheet(title="URL信息")
    ws.column_dimensions['A'].width = 62.0
    ws.column_dimensions['B'].width = 46.0
    ws.column_dimensions['C'].width = 52.0
    ws.column_dimensions['D'].width = 10.0
    ws.column_dimensions['E'].width = 12.0
    ws.column_dimensions['F'].width = 24.0
    ws.append(["URL", "站点", "标题", "状态码", "body长度", "来源"])

    for row in _extract_url_rows(task_ids):
        ws.append(row)

    set_sheet_style(ws)


def _build_fileleak_sheet(wb, task_ids):
    """
    在导出工作簿中新增目录扫描工作表。
    """
    ws = wb.create_sheet(title="目录扫描")
    ws.column_dimensions['A'].width = 62.0
    ws.column_dimensions['B'].width = 46.0
    ws.column_dimensions['C'].width = 52.0
    ws.column_dimensions['D'].width = 10.0
    ws.column_dimensions['E'].width = 12.0
    ws.append(["URL", "站点", "标题", "状态码", "body长度"])

    for row in _extract_fileleak_rows(task_ids):
        ws.append(row)

    set_sheet_style(ws)


def _build_wih_sheet(wb, task_ids):
    """
    在导出工作簿中新增 WIH 工作表。
    """
    ws = wb.create_sheet(title="WIH")
    ws.column_dimensions['A'].width = 22.0
    ws.column_dimensions['B'].width = 64.0
    ws.column_dimensions['C'].width = 52.0
    ws.column_dimensions['D'].width = 46.0
    ws.append(["记录类型", "内容", "来源", "站点"])

    for row in _extract_wih_rows(task_ids):
        ws.append(row)

    set_sheet_style(ws)


def _cert_record_rank(item):
    """
    证书记录优先级（值越小优先级越高）：
    1) scan_mode=sni
    2) 有 sni_domain
    3) 有 domain
    """
    if not isinstance(item, dict):
        return (9, 9, 9)

    scan_mode = sanitize_excel_value(item.get("scan_mode", "")).strip().lower()
    sni_domain = _normalize_cert_domain(item.get("sni_domain", ""))
    item_domain = _normalize_cert_domain(item.get("domain", ""))

    mode_rank = 0 if scan_mode == "sni" else 1
    sni_rank = 0 if sni_domain else 1
    domain_rank = 0 if item_domain else 1
    return (mode_rank, sni_rank, domain_rank)


def _select_preferred_cert_items(cert_items):
    """
    按 task_id+ip+port 聚合证书记录，优先保留业务域名证书，抑制 default 默认证书干扰。
    """
    if not isinstance(cert_items, list):
        return []

    grouped = {}
    for item in cert_items:
        if not isinstance(item, dict):
            continue

        task_id = sanitize_excel_value(item.get("task_id", "")).strip()
        ip = sanitize_excel_value(item.get("ip", "")).strip()
        port = sanitize_excel_value(item.get("port", "")).strip()
        if not task_id or not ip or not port:
            # 结构异常记录按原样保留，避免误丢数据
            key = ("raw", str(len(grouped)))
            grouped[key] = item
            continue

        key = (task_id, ip, port)
        current = grouped.get(key)
        if not current:
            grouped[key] = item
            continue

        if _cert_record_rank(item) < _cert_record_rank(current):
            grouped[key] = item

    return list(grouped.values())


def _parse_datetime_safe(value):
    """
    兼容多种时间字符串格式，解析失败时返回 None。
    """
    text = sanitize_excel_value(value).strip()
    if not text:
        return None

    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]:
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            continue

    return None


def _normalize_cert_domain(value):
    """
    归一化证书相关域名文本，非法值返回空字符串。
    """
    domain = utils.normalize_domain(sanitize_excel_value(value))
    if not utils.is_valid_domain(domain):
        return ""
    return domain


def _extract_cert_san_domains(cert_obj):
    """
    从证书扩展字段提取 SAN 域名列表。
    """
    if not isinstance(cert_obj, dict):
        return []

    extensions = cert_obj.get("extensions", {})
    if not isinstance(extensions, dict):
        return []

    san_text = sanitize_excel_value(extensions.get("subjectAltName", ""))
    if not san_text:
        return []

    domains = []
    seen = set()
    for part in san_text.split(","):
        item = sanitize_excel_value(part).strip()
        if not item:
            continue

        if ":" in item:
            prefix, value = item.split(":", 1)
            if prefix.strip().upper() != "DNS":
                continue
            candidate = value.strip()
        else:
            candidate = item

        domain = _normalize_cert_domain(candidate)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)

    return domains


def _build_cert_domain_context(task_id):
    """
    构建任务级 IP->域名映射，供 SSL 证书导出补全域名。
    """
    ip_domain_map = {}
    task_domain_set = set()

    for item in get_domain_data(task_id):
        domain = _normalize_cert_domain(item.get("domain", ""))
        if not domain:
            continue
        task_domain_set.add(domain)

        raw_ips = item.get("ips", [])
        if isinstance(raw_ips, str):
            raw_ips = [x.strip() for x in raw_ips.split(",") if x.strip()]
        if not isinstance(raw_ips, list):
            raw_ips = []

        for raw_ip in raw_ips:
            ip = sanitize_excel_value(raw_ip).strip()
            if not ip:
                continue
            ip_domain_map.setdefault(ip, []).append(domain)

    for item in get_ip_data(task_id):
        ip = sanitize_excel_value(item.get("ip", "")).strip()
        if not ip:
            continue

        raw_domains = item.get("domain", [])
        if isinstance(raw_domains, str):
            raw_domains = [raw_domains]
        if not isinstance(raw_domains, list):
            raw_domains = []

        for raw_domain in raw_domains:
            domain = _normalize_cert_domain(raw_domain)
            if not domain:
                continue
            task_domain_set.add(domain)
            ip_domain_map.setdefault(ip, []).append(domain)

    for ip, domains in list(ip_domain_map.items()):
        ordered = []
        seen = set()
        for domain in domains:
            if domain in seen:
                continue
            ordered.append(domain)
            seen.add(domain)
        ip_domain_map[ip] = ordered

    return ip_domain_map, task_domain_set


def _resolve_cert_domain(item, cert_obj, ip_domain_map=None, task_domain_set=None):
    """
    导出域名优先级：
    1) cert 记录中的 sni_domain/domain/domains
    2) 任务内 IP 关联域名
    3) SAN（优先命中任务域名）
    4) CN
    """
    ip_domain_map = ip_domain_map if isinstance(ip_domain_map, dict) else {}
    task_domain_set = task_domain_set if isinstance(task_domain_set, set) else set()

    sni_domain = _normalize_cert_domain(item.get("sni_domain", ""))
    if sni_domain:
        return sni_domain

    item_domain = _normalize_cert_domain(item.get("domain", ""))
    if item_domain:
        return item_domain

    scan_mode = sanitize_excel_value(item.get("scan_mode", "")).strip().lower()
    if scan_mode == "sni":
        item_domains = item.get("domains", [])
        if isinstance(item_domains, str):
            item_domains = [item_domains]
        if isinstance(item_domains, list):
            for domain in item_domains:
                normalized = _normalize_cert_domain(domain)
                if normalized:
                    return normalized

    ip = sanitize_excel_value(item.get("ip", "")).strip()
    mapped_domains = ip_domain_map.get(ip, [])
    if isinstance(mapped_domains, list):
        for domain in mapped_domains:
            if domain:
                return domain

    san_domains = _extract_cert_san_domains(cert_obj)
    if task_domain_set:
        for domain in san_domains:
            if domain in task_domain_set:
                return domain
    if san_domains:
        return san_domains[0]

    subject = cert_obj.get("subject", {}) if isinstance(cert_obj, dict) else {}
    if isinstance(subject, dict):
        common_name = _normalize_cert_domain(subject.get("common_name", ""))
        if common_name:
            return common_name

    return ""


def _extract_protocol_names(ssl_security):
    """
    从证书安全字段中提取协议名称列表。
    """
    if not isinstance(ssl_security, dict):
        return []

    names = []
    protocols = ssl_security.get("protocols", [])
    if isinstance(protocols, list):
        for item in protocols:
            if isinstance(item, dict):
                name = sanitize_excel_value(item.get("name", "")).strip()
            else:
                name = sanitize_excel_value(item).strip()
            if name:
                names.append(name)

    if not names and isinstance(ssl_security.get("protocol_names"), list):
        for name in ssl_security.get("protocol_names", []):
            text = sanitize_excel_value(name).strip()
            if text:
                names.append(text)

    return sorted(list(set(names)))


def _extract_cipher_suite_lines(ssl_security, max_items=50):
    """
    组装加密套件文本（协议 + 套件 + 强度），并限制导出长度。
    """
    if not isinstance(ssl_security, dict):
        return []

    lines = []
    cipher_suites = ssl_security.get("cipher_suites", [])
    if not isinstance(cipher_suites, list):
        return lines

    for item in cipher_suites:
        if not isinstance(item, dict):
            continue
        protocol = sanitize_excel_value(item.get("protocol", "")).strip()
        cipher_name = sanitize_excel_value(item.get("name", "")).strip()
        strength = sanitize_excel_value(item.get("strength", "")).strip().upper()
        if not cipher_name:
            continue
        line = cipher_name
        if protocol:
            line = "[{}] {}".format(protocol, line)
        if strength:
            line = "{} ({})".format(line, strength)
        lines.append(line)

    if len(lines) > max_items:
        hidden = len(lines) - max_items
        lines = lines[:max_items]
        lines.append("... 其余 {} 条省略".format(hidden))

    return lines


def _extract_cert_rows(task_ids):
    """
    汇总 SSL 证书导出行（支持协议/套件/强度信息）。
    """
    rows = []
    now_dt = datetime.utcnow()

    for task_id in task_ids:
        task_id = str(task_id or "").strip()
        if not task_id:
            continue

        ip_domain_map, task_domain_set = _build_cert_domain_context(task_id)
        cert_items = list(get_cert_data(task_id))
        for item in _select_preferred_cert_items(cert_items):
            cert_obj = item.get("cert", {}) if isinstance(item.get("cert"), dict) else {}
            validity = cert_obj.get("validity", {}) if isinstance(cert_obj.get("validity"), dict) else {}
            ssl_security = cert_obj.get("ssl_security", {}) if isinstance(cert_obj.get("ssl_security"), dict) else {}

            ip = sanitize_excel_value(item.get("ip", "")).strip()
            port = sanitize_excel_value(item.get("port", "")).strip()
            host = sanitize_excel_value(item.get("host", "")).strip()
            if not host:
                host = "{}:{}".format(ip, port) if ip and port else ip or port

            domain = _resolve_cert_domain(
                item=item,
                cert_obj=cert_obj,
                ip_domain_map=ip_domain_map,
                task_domain_set=task_domain_set,
            )
            if not domain:
                domain = "-"

            validity_start = sanitize_excel_value(validity.get("start", "")).strip()
            validity_end = sanitize_excel_value(validity.get("end", "")).strip()

            remain_days = ""
            end_dt = _parse_datetime_safe(validity_end)
            if end_dt:
                remain_days = (end_dt - now_dt).days

            protocol_names = _extract_protocol_names(ssl_security)
            protocol_text = "、".join(protocol_names)

            least_strength = sanitize_excel_value(ssl_security.get("least_strength", "")).strip().upper()
            ecdhe_count = ssl_security.get("ecdhe_count", "")
            try:
                ecdhe_count = int(ecdhe_count)
            except Exception:
                ecdhe_count = ""

            cipher_lines = _extract_cipher_suite_lines(ssl_security)
            cipher_text = " \r\n".join(cipher_lines)

            sha256 = ""
            fingerprint = cert_obj.get("fingerprint", {})
            if isinstance(fingerprint, dict):
                sha256 = sanitize_excel_value(fingerprint.get("sha256", "")).strip()

            san = ""
            extensions = cert_obj.get("extensions", {})
            if isinstance(extensions, dict):
                san = sanitize_excel_value(extensions.get("subjectAltName", "")).strip()

            rows.append(
                [
                    sanitize_excel_value(domain),
                    sanitize_excel_value(host),
                    sanitize_excel_value(cert_obj.get("subject_dn", "")),
                    sanitize_excel_value(cert_obj.get("issuer_dn", "")),
                    sanitize_excel_value(validity_start),
                    sanitize_excel_value(validity_end),
                    sanitize_excel_value(remain_days),
                    sanitize_excel_value(protocol_text),
                    sanitize_excel_value(least_strength),
                    sanitize_excel_value(ecdhe_count),
                    sanitize_excel_value(cipher_text),
                    sanitize_excel_value(sha256),
                    sanitize_excel_value(san),
                ]
            )

    return rows


def _build_cert_sheet(wb, task_ids):
    """
    在导出工作簿中新增 SSL 证书工作表。
    """
    ws = wb.create_sheet(title="SSL证书")
    ws.column_dimensions['A'].width = 32.0
    ws.column_dimensions['B'].width = 26.0
    ws.column_dimensions['C'].width = 40.0
    ws.column_dimensions['D'].width = 40.0
    ws.column_dimensions['E'].width = 21.0
    ws.column_dimensions['F'].width = 21.0
    ws.column_dimensions['G'].width = 12.0
    ws.column_dimensions['H'].width = 24.0
    ws.column_dimensions['I'].width = 12.0
    ws.column_dimensions['J'].width = 14.0
    ws.column_dimensions['K'].width = 68.0
    ws.column_dimensions['L'].width = 42.0
    ws.column_dimensions['M'].width = 60.0

    ws.append(
        [
            "域名",
            "HOST",
            "主题名称",
            "签发者名称",
            "生效时间",
            "失效时间",
            "剩余天数",
            "支持协议",
            "最弱强度",
            "ECDHE套件数",
            "加密套件",
            "SHA-256",
            "使用者备用名称",
        ]
    )

    for row in _extract_cert_rows(task_ids):
        ws.append(row)

    beautify_cert_sheet(ws)


def _extract_vuln_rows(task_ids):
    """
    汇总漏洞明细（合并 vuln 与 nuclei_result），并按关键字段去重
    """
    rows = []
    dedup_keys = set()

    for task_id in task_ids:
        task_id = str(task_id or "").strip()
        if not task_id:
            continue

        for item in get_vuln_data(task_id):
            vuln_name = sanitize_excel_value(item.get("vul_name", ""))
            severity = sanitize_excel_value(item.get("severity", ""))
            target = sanitize_excel_value(item.get("target", ""))
            vuln_url = target if str(target).startswith("http") else ""
            plugin = sanitize_excel_value(item.get("plg_name", ""))
            vuln_type = sanitize_excel_value(item.get("plg_type", ""))
            detail = sanitize_excel_value(
                item.get("description", "")
                or item.get("detail", "")
                or item.get("verify_data", "")
            )

            dedup_key = (
                task_id, "npoc", vuln_name, severity, target, vuln_url, plugin, vuln_type
            )
            if dedup_key in dedup_keys:
                continue
            dedup_keys.add(dedup_key)
            rows.append(
                [
                    "npoc",
                    vuln_name,
                    severity,
                    target,
                    vuln_url,
                    plugin,
                    vuln_type,
                    detail,
                ]
            )

        for item in get_nuclei_result_data(task_id):
            vuln_name = sanitize_excel_value(item.get("vuln_name", ""))
            severity = sanitize_excel_value(item.get("vuln_severity", ""))
            target = sanitize_excel_value(item.get("target", ""))
            vuln_url = sanitize_excel_value(item.get("vuln_url", ""))
            template_id = sanitize_excel_value(item.get("template_id", ""))
            template_url = sanitize_excel_value(item.get("template_url", ""))

            dedup_key = (
                task_id, "nuclei", vuln_name, severity, target, vuln_url, template_id
            )
            if dedup_key in dedup_keys:
                continue
            dedup_keys.add(dedup_key)
            rows.append(
                [
                    "nuclei",
                    vuln_name,
                    severity,
                    target,
                    vuln_url,
                    template_id,
                    "nuclei",
                    template_url,
                ]
            )

    return rows


def _build_vuln_sheet(wb, task_ids):
    """
    在导出工作簿中新增风险明细工作表
    """
    ws = wb.create_sheet(title="风险")
    ws.column_dimensions['A'].width = 12.0
    ws.column_dimensions['B'].width = 36.0
    ws.column_dimensions['C'].width = 14.0
    ws.column_dimensions['D'].width = 36.0
    ws.column_dimensions['E'].width = 60.0
    ws.column_dimensions['F'].width = 28.0
    ws.column_dimensions['G'].width = 20.0
    ws.column_dimensions['H'].width = 80.0

    ws.append(["来源", "风险名称", "严重级别", "目标", "风险URL", "模板/插件", "风险类型", "详情"])
    for row in _extract_vuln_rows(task_ids):
        ws.append(row)

    set_sheet_style(ws)


def port_service_product_statist(task_id):
    """
    端口和服务统计分析
    
    参数：
        task_id: 任务ID
    
    返回：
        tuple: (端口Top20列表, 服务Top20列表)
    
    说明：
    - 统计开放端口的分布情况
    - 统计识别的服务类型分布
    - 返回Top20排行榜
    """
    ip_data = get_ip_data(task_id)
    total = 0
    port_info_list = []
    
    # 收集所有端口信息
    for item in ip_data:
        if not item["port_info"]:
            continue
        port_info_list.extend(item["port_info"])
        total += len(item["port_info"])

    # 统计端口分布Top20
    counter = Counter([info["port_id"] for info in port_info_list])
    top_20 = counter.most_common(20)
    port_percent_list = []
    for port_info in top_20:
        port_id, amount = port_info
        item = {
            "port_id" : port_id,
            "amount" : amount,
            "percent" : "{:.2f}%".format((amount *100.0 ) / total)
        }
        port_percent_list.append(item)

    # 统计服务类型分布
    service_name_list = []
    for info in port_info_list:
        if  not  info.get("product"):
            continue
        if info["product"] or info["version"]:
            service_name = info["service_name"]
            if service_name == "https-alt":
                service_name = "https"

            service_name_list.append(service_name)

    service_top_20 = Counter(service_name_list).most_common(20)

    service_percent_list = []
    for port_info in service_top_20:
        service_name, amount = port_info
        item = {
            "service_name" : service_name,
            "amount" : amount,
            "percent" : "{:.2f}%".format((amount *100.0 ) / len(service_name_list))
        }
        service_percent_list.append(item)



    product_name_list = []
    for info in port_info_list:
        if not info.get("product"):
            continue
        product = info["product"]
        if product and "**" not in product:
            product = product.strip()
            product_name_list.append(product)

    product_top_20 = Counter(product_name_list).most_common(20)
    product_percent_list = []
    for info in product_top_20:
        product, amount = info
        item = {
            "product" : product,
            "amount" : amount,
            "percent" : "{:.2f}%".format((amount *100.0 ) / len(product_name_list))
        }
        product_percent_list.append(item)

    statist = {
        "port_total": total, #端口开放总数
        "port_percent_list": port_percent_list, #端口开放 top 20比例详情
        "service_total": len(service_name_list),  #系统服务类别总数
        "service_percent_list": service_percent_list, #系统服务类别 top 20比例详情
        "product_total": len(product_name_list), #产品种类总数
        "product_percent_list": product_percent_list ##产品种类总数 top 20比例详情
    }
    return statist



class SaveTask(object):
    """docstring for ClassName"""

    def __init__(self, task_id):
        self.task_id = task_id
        self.wb = Workbook()
        self.is_ip_task = False

    def set_style(self, ws):
        set_sheet_style(ws)

    def build_service_xl(self):
        ws = self.wb.create_sheet(title="系统服务")
        ws.column_dimensions['A'].width = 22.0
        ws.column_dimensions['B'].width = 10.0
        ws.column_dimensions['C'].width = 20.0
        ws.column_dimensions['D'].width = 40.0

        column_tilte = ["IP", "端口","服务", "产品", "版本"]
        ws.append(column_tilte)
        fallback_ip_items = list(get_ip_data(self.task_id))
        for row in _build_service_rows([self.task_id], fallback_ip_items=fallback_ip_items):
            ws.append([
                sanitize_excel_value(row[0]),
                sanitize_excel_value(row[1]),
                sanitize_excel_value(row[2]),
                sanitize_excel_value(row[3]),
                sanitize_excel_value(row[4]),
            ])

        self.set_style(ws)

    def build_ip_xl(self):
        ws = self.wb.create_sheet(title="IP")
        ws.column_dimensions['A'].width = 22.0
        ws.column_dimensions['B'].width = 50.0
        ws.column_dimensions['C'].width = 10.0
        ws.column_dimensions['D'].width = 25.0
        ws.column_dimensions['E'].width = 55.0
        if self.is_ip_task:
            ws.column_dimensions['F'].width = 55.0
            column_tilte = ["IP", "端口信息", "开放端口数目", "geo", "as 编号", "操作系统"]
            ws.append(column_tilte)
            for item in get_ip_data(self.task_id):
                row = []
                row.append(item["ip"])

                port_ids = [str(x["port_id"]) for x in item["port_info"]]
                row.append(" \r\n".join(port_ids))
                row.append(len(item["port_info"]))
                if "country_name" in item["geo_city"]:
                    row.append("{}/{}".format(item["geo_city"]["country_name"],
                                              item["geo_city"]["region_name"]))
                    row.append(item["geo_asn"].get("organization", ""))
                else:
                    row.append("")
                    row.append("")

                osname = ""
                if item.get("os_info"):
                    osname = item["os_info"]["name"]
                row.append(osname)
                ws.append(row)
        else:
            ws.column_dimensions['F'].width = 60.0
            ws.column_dimensions['G'].width = 40.0
            ws.column_dimensions['H'].width = 40.0
            ws.column_dimensions['I'].width = 20.0
            column_tilte = ["IP", "端口信息", "开放端口数目", "geo", "as 编号"]
            column_tilte.append("domain")
            column_tilte.append("操作系统")
            column_tilte.append("CDN")
            column_tilte.append("类别")
            ws.append(column_tilte)
            for item in get_ip_data(self.task_id):
                row = []
                row.append(item["ip"])

                port_ids = [str(x["port_id"]) for x in item["port_info"]]
                row.append(" \r\n".join(port_ids))

                row.append(len(item["port_info"]))
                if "country_name" in item["geo_city"]:
                    row.append("{}/{}".format(item["geo_city"]["country_name"],
                                              item["geo_city"]["region_name"]))
                    row.append(item["geo_asn"].get("organization", ""))
                else:
                    row.append("")
                    row.append("")

                row.append(" \r\n".join(item.get("domain", [])))

                osname = ""
                if item.get("os_info"):
                    osname = item["os_info"]["name"]
                row.append(osname)
                row.append(item.get("cdn_name", ""))
                row.append(item.get("ip_type", ""))
                ws.append(row)

        self.set_style(ws)

    def ignore_illegal(self, content):
        ILLEGAL_CHARACTERS_RE = re.compile(r'[\000-\010]|[\013-\014]|[\016-\037]')
        content = ILLEGAL_CHARACTERS_RE.sub(r'', content)
        return content

    def build_site_xl(self):
        ws = self.wb.active
        ws.column_dimensions['A'].width = 35.0
        ws.column_dimensions['B'].width = 40.0
        ws.column_dimensions['C'].width = 60.0
        ws.column_dimensions['D'].width = 20.0
        ws.column_dimensions['E'].width = 30.0
        ws.title = "站点"
        column_tilte = ["site", "title", "指纹", "状态码", "favicon hash"]
        ws.append(column_tilte)
        for item in get_site_data(self.task_id):
            row = []
            row.append(self.ignore_illegal(item["site"]))
            row.append(self.ignore_illegal(item["title"]))
            row.append(" \r\n".join([self.ignore_illegal(x["name"]) for x in item["finger"]]))
            row.append(item["status"])
            row.append(item["favicon"].get("hash", ""))
            ws.append(row)

        self.set_style(ws)

    def build_domain_xl(self):
        ws = self.wb.create_sheet(title="域名")
        ws.column_dimensions['A'].width = 30.0
        ws.column_dimensions['B'].width = 20.0
        ws.column_dimensions['C'].width = 50.0
        ws.column_dimensions['D'].width = 50.0

        column_tilte = ["域名", "解析类型", "记录值","关联ip"]

        ws.append(column_tilte)
        for item in get_domain_data(self.task_id):
            row = []
            row.append(item["domain"])
            row.append(item["type"])
            row.append(" \r\n".join(item["record"]))
            row.append(" \r\n".join(item["ips"]))
            ws.append(row)

        self.set_style(ws)

    def build_url_xl(self):
        """
        构建 URL 信息工作表。
        """
        _build_url_sheet(self.wb, [self.task_id])

    def build_fileleak_xl(self):
        """
        构建目录扫描工作表。
        """
        _build_fileleak_sheet(self.wb, [self.task_id])

    def build_wih_xl(self):
        """
        构建 WIH 工作表。
        """
        _build_wih_sheet(self.wb, [self.task_id])

    def build_cert_xl(self):
        """
        生成 SSL 证书工作表（协议/套件/强度）。
        """
        _build_cert_sheet(self.wb, [self.task_id])

    def build_statist(self):
        statist = port_service_product_statist(self.task_id)
        ws = self.wb.create_sheet(title="资产统计")
        ws.column_dimensions['A'].width = 20.0
        ws.column_dimensions['F'].width = 20.0
        ws.column_dimensions['K'].width = 40.0
        ws["A1"] = "端口信息统计"
        ws["F1"] = "系统服务信息统计"
        ws["K1"] = "软件产品信息统计"

        ports = ["端口", "数量", "占比"]
        port_percent_list = statist["port_percent_list"]
        port_total = statist["port_total"]
        for port_info in port_percent_list:
            ports.append(port_info["port_id"])
            ports.append(port_info["amount"])
            ports.append(port_info["percent"])

        cnt = 0
        for row in range(5, 27):
            for col in range(1, 4):
                if cnt >= len(ports):
                    continue
                ws.cell(column=col, row=row, value=ports[cnt])
                cnt += 1

        ws["A27"] = "端口开放总数"
        ws["A28"] = port_total

        services = ["系统服务", "数量", "占比"]
        service_percent_list = statist["service_percent_list"]
        if len(service_percent_list) >= 0:
            service_total = statist["service_total"]
            for port_info in service_percent_list:
                services.append(port_info["service_name"])
                services.append(port_info["amount"])
                services.append(port_info["percent"])
            cnt = 0
            for row in range(5, 27):
                for col in range(6, 9):
                    if cnt >= len(services):
                        continue
                    ws.cell(column=col, row=row, value=services[cnt])
                    cnt += 1
            ws["F27"] = "系统服务类别总数"
            ws["F28"] = service_total

        product = ["产品", "数量", "占比"]
        product_percent_list = statist["product_percent_list"]
        if len(product_percent_list) >= 0:
            product_total = statist["product_total"]
            for port_info in product_percent_list:
                product.append(port_info["product"])
                product.append(port_info["amount"])
                product.append(port_info["percent"])
            cnt = 0
            for row in range(5, 27):
                for col in range(11, 14):
                    if cnt >= len(product):
                        continue
                    ws.cell(column=col, row=row, value=product[cnt])
                    cnt += 1
            ws["K27"] = "产品类别总数"
            ws["K28"] = product_total

        self.set_style(ws)

    def build_vuln_xl(self):
        _build_vuln_sheet(self.wb, [self.task_id])

    def run(self):
        task_data = get_task_data(self.task_id)
        if not task_data:
            print("not found {}".format(self.task_id))
            return

        domain = task_data["target"].replace("/", "_")[:20]

        if re.findall(r"\b\d+\.\d+\.\d+\.\d+", domain):
            self.is_ip_task = True
        else:
            if task_data.get("type", "") == "ip":
                self.is_ip_task = True

        self.build_site_xl()
        self.build_ip_xl()
        self.build_service_xl()
        self.build_cert_xl()
        self.build_domain_xl()
        self.build_url_xl()
        self.build_fileleak_xl()
        self.build_wih_xl()
        self.build_statist()

        return save_virtual_workbook(self.wb)


def export_arl(task_id):
    task_id = task_id.strip()
    save = SaveTask(task_id)
    return save.run()


def export_merge_tasks(task_id_list):
    """
    整合导出多个任务的数据
    
    参数：
        task_id_list: 任务ID列表
    
    返回：
        合并后的Excel文件二进制数据
    
    说明：
    - 合并多个任务的所有扫描数据
    - 按照单个任务的导出格式生成报告
    - 保留任务原始IP/服务明细（不做跨任务折叠），保证与页面口径一致
    - 域名、站点仍按值合并去重，避免重复噪音
    """
    wb = Workbook()
    if 'Sheet' in wb.sheetnames:
        wb.remove(wb['Sheet'])

    valid_tasks = []
    valid_task_ids = []
    for task_id in task_id_list:
        if not task_id:
            continue
        task_data = get_task_data(task_id)
        if task_data:
            valid_tasks.append(task_data)
            valid_task_ids.append(str(task_data.get("_id", "")))

    if not valid_tasks:
        raise ValueError("未找到可导出的任务数据")

    # 与单任务保持一致：仅当全部任务都是 IP 类型时，按 IP 任务列导出；否则按通用任务列导出
    is_ip_task = True
    for task_data in valid_tasks:
        target = sanitize_excel_value(task_data.get("target", ""))
        if not (re.findall(r"\b\d+\.\d+\.\d+\.\d+", target) or task_data.get("type", "") == "ip"):
            is_ip_task = False
            break

    merged_ip_items = []  # 保留原始 ip 文档（不跨任务合并）
    merged_domains = {}   # key: domain
    merged_sites = {}     # key: site

    for task_data in valid_tasks:
        task_id = str(task_data.get("_id"))

        for ip_item in get_ip_data(task_id):
            ip = sanitize_excel_value(ip_item.get("ip", "")).strip()
            if not ip:
                continue

            port_info_list = []
            for port_info in as_list(ip_item.get("port_info", [])):
                if isinstance(port_info, dict):
                    port_info_list.append(port_info)

            domain_list = []
            domain_seen = set()
            for domain in as_list(ip_item.get("domain", [])):
                domain_text = sanitize_excel_value(domain).strip()
                if not domain_text or domain_text in domain_seen:
                    continue
                domain_seen.add(domain_text)
                domain_list.append(domain_text)

            merged_ip_items.append({
                "task_id": task_id,
                "ip": ip,
                "port_info": port_info_list,
                "geo_city": ip_item.get("geo_city", {}) if isinstance(ip_item.get("geo_city", {}), dict) else {},
                "geo_asn": ip_item.get("geo_asn", {}) if isinstance(ip_item.get("geo_asn", {}), dict) else {},
                "domain": domain_list,
                "os_info": ip_item.get("os_info", {}) if isinstance(ip_item.get("os_info", {}), dict) else {},
                "cdn_name": ip_item.get("cdn_name", ""),
                "ip_type": ip_item.get("ip_type", ""),
            })

        for domain_item in get_domain_data(task_id):
            domain = domain_item.get("domain")
            if not domain:
                continue
            if domain not in merged_domains:
                merged_domains[domain] = {
                    "domain": domain,
                    "type": domain_item.get("type", ""),
                    "record": as_list(domain_item.get("record", [])),
                    "ips": as_list(domain_item.get("ips", [])),
                }
            else:
                merged = merged_domains[domain]
                if not merged.get("type") and domain_item.get("type"):
                    merged["type"] = domain_item.get("type")
                merged["record"] = sorted(list(set(merged.get("record", []) + as_list(domain_item.get("record", [])))))
                merged["ips"] = sorted(list(set(merged.get("ips", []) + as_list(domain_item.get("ips", [])))))

        for site_item in get_site_data(task_id):
            site = site_item.get("site") or site_item.get("url")
            if not site:
                continue
            if site not in merged_sites:
                merged_sites[site] = {
                    "site": site,
                    "title": site_item.get("title", ""),
                    "finger": as_list(site_item.get("finger", [])),
                    "status": site_item.get("status", ""),
                    "favicon": site_item.get("favicon", {}),
                }
            else:
                merged = merged_sites[site]
                if not merged.get("title") and site_item.get("title"):
                    merged["title"] = site_item.get("title", "")
                if not merged.get("status") and site_item.get("status"):
                    merged["status"] = site_item.get("status", "")
                if (not isinstance(merged.get("favicon"), dict) or not merged.get("favicon", {}).get("hash")) and \
                        isinstance(site_item.get("favicon"), dict):
                    merged["favicon"] = site_item.get("favicon", {})

                # 按指纹名称去重
                name_set = set()
                new_fingers = []
                for finger in as_list(merged.get("finger", [])) + as_list(site_item.get("finger", [])):
                    if isinstance(finger, dict):
                        name = sanitize_excel_value(finger.get("name", ""))
                        key = ("dict", name)
                    else:
                        name = sanitize_excel_value(finger)
                        key = ("str", name)
                    if key in name_set:
                        continue
                    name_set.add(key)
                    new_fingers.append(finger)
                merged["finger"] = new_fingers

    if not merged_ip_items and not merged_domains and not merged_sites:
        raise ValueError("未找到可导出的任务数据")

    # 站点（与单任务导出同结构）
    ws = wb.create_sheet(title="站点")
    ws.column_dimensions['A'].width = 35.0
    ws.column_dimensions['B'].width = 40.0
    ws.column_dimensions['C'].width = 60.0
    ws.column_dimensions['D'].width = 20.0
    ws.column_dimensions['E'].width = 30.0
    ws.append(["site", "title", "指纹", "状态码", "favicon hash"])
    for site in sorted(merged_sites.keys()):
        item = merged_sites[site]
        ws.append([
            sanitize_excel_value(item.get("site", "")),
            sanitize_excel_value(item.get("title", "")),
            sanitize_excel_value(extract_finger_names(item.get("finger", []))).replace(",", " \r\n"),
            sanitize_excel_value(item.get("status", "")),
            sanitize_excel_value((item.get("favicon", {}) or {}).get("hash", "")),
        ])
    set_sheet_style(ws)

    # IP（与单任务导出同结构）
    ws = wb.create_sheet(title="IP")
    ws.column_dimensions['A'].width = 22.0
    ws.column_dimensions['B'].width = 50.0
    ws.column_dimensions['C'].width = 10.0
    ws.column_dimensions['D'].width = 25.0
    ws.column_dimensions['E'].width = 55.0

    if is_ip_task:
        ws.column_dimensions['F'].width = 55.0
        ws.append(["IP", "端口信息", "开放端口数目", "geo", "as 编号", "操作系统"])
        for item in merged_ip_items:
            port_ids = [str(x.get("port_id")) for x in item.get("port_info", []) if x.get("port_id") is not None]
            geo_city = item.get("geo_city", {}) if isinstance(item.get("geo_city", {}), dict) else {}
            geo_asn = item.get("geo_asn", {}) if isinstance(item.get("geo_asn", {}), dict) else {}
            geo_text = ""
            as_text = ""
            if "country_name" in geo_city:
                geo_text = "{}/{}".format(geo_city.get("country_name", ""), geo_city.get("region_name", ""))
                as_text = geo_asn.get("organization", "")
            osname = ""
            if isinstance(item.get("os_info", {}), dict):
                osname = item.get("os_info", {}).get("name", "")
            ws.append([
                sanitize_excel_value(item.get("ip", "")),
                sanitize_excel_value(" \r\n".join(port_ids)),
                len(item.get("port_info", [])),
                sanitize_excel_value(geo_text),
                sanitize_excel_value(as_text),
                sanitize_excel_value(osname),
            ])
    else:
        ws.column_dimensions['F'].width = 60.0
        ws.column_dimensions['G'].width = 40.0
        ws.column_dimensions['H'].width = 40.0
        ws.column_dimensions['I'].width = 20.0
        ws.append(["IP", "端口信息", "开放端口数目", "geo", "as 编号", "domain", "操作系统", "CDN", "类别"])
        for item in merged_ip_items:
            port_ids = [str(x.get("port_id")) for x in item.get("port_info", []) if x.get("port_id") is not None]
            geo_city = item.get("geo_city", {}) if isinstance(item.get("geo_city", {}), dict) else {}
            geo_asn = item.get("geo_asn", {}) if isinstance(item.get("geo_asn", {}), dict) else {}
            geo_text = ""
            as_text = ""
            if "country_name" in geo_city:
                geo_text = "{}/{}".format(geo_city.get("country_name", ""), geo_city.get("region_name", ""))
                as_text = geo_asn.get("organization", "")
            osname = ""
            if isinstance(item.get("os_info", {}), dict):
                osname = item.get("os_info", {}).get("name", "")
            ws.append([
                sanitize_excel_value(item.get("ip", "")),
                sanitize_excel_value(" \r\n".join(port_ids)),
                len(item.get("port_info", [])),
                sanitize_excel_value(geo_text),
                sanitize_excel_value(as_text),
                sanitize_excel_value(" \r\n".join(as_list(item.get("domain", [])))),
                sanitize_excel_value(osname),
                sanitize_excel_value(item.get("cdn_name", "")),
                sanitize_excel_value(item.get("ip_type", "")),
            ])
    set_sheet_style(ws)

    # 系统服务（与单任务导出同结构）
    ws = wb.create_sheet(title="系统服务")
    ws.column_dimensions['A'].width = 22.0
    ws.column_dimensions['B'].width = 10.0
    ws.column_dimensions['C'].width = 20.0
    ws.column_dimensions['D'].width = 40.0
    ws.append(["IP", "端口", "服务", "产品", "版本"])
    for row in _build_service_rows(valid_task_ids, fallback_ip_items=merged_ip_items):
        ws.append([
            sanitize_excel_value(row[0]),
            sanitize_excel_value(row[1]),
            sanitize_excel_value(row[2]),
            sanitize_excel_value(row[3]),
            sanitize_excel_value(row[4]),
        ])
    set_sheet_style(ws)

    _build_cert_sheet(wb, valid_task_ids)

    # 域名（统一保留，IP任务为空时仅输出表头）
    ws = wb.create_sheet(title="域名")
    ws.column_dimensions['A'].width = 30.0
    ws.column_dimensions['B'].width = 20.0
    ws.column_dimensions['C'].width = 50.0
    ws.column_dimensions['D'].width = 50.0
    ws.append(["域名", "解析类型", "记录值", "关联ip"])
    for domain in sorted(merged_domains.keys()):
        item = merged_domains[domain]
        ws.append([
            sanitize_excel_value(item.get("domain", "")),
            sanitize_excel_value(item.get("type", "")),
            sanitize_excel_value(" \r\n".join(as_list(item.get("record", [])))),
            sanitize_excel_value(" \r\n".join(as_list(item.get("ips", [])))),
        ])
    set_sheet_style(ws)

    # URL信息 / 目录扫描 / WIH（与单任务导出顺序保持一致）
    _build_url_sheet(wb, valid_task_ids)
    _build_fileleak_sheet(wb, valid_task_ids)
    _build_wih_sheet(wb, valid_task_ids)

    # 资产统计（与单任务导出同结构）
    statist = calc_port_service_product_statist_from_ip_items(merged_ip_items)
    ws = wb.create_sheet(title="资产统计")
    ws.column_dimensions['A'].width = 20.0
    ws.column_dimensions['F'].width = 20.0
    ws.column_dimensions['K'].width = 40.0
    ws["A1"] = "端口信息统计"
    ws["F1"] = "系统服务信息统计"
    ws["K1"] = "软件产品信息统计"

    ports = ["端口", "数量", "占比"]
    for port_info in statist["port_percent_list"]:
        ports.extend([port_info["port_id"], port_info["amount"], port_info["percent"]])
    cnt = 0
    for row in range(5, 27):
        for col in range(1, 4):
            if cnt >= len(ports):
                continue
            ws.cell(column=col, row=row, value=ports[cnt])
            cnt += 1
    ws["A27"] = "端口开放总数"
    ws["A28"] = statist["port_total"]

    services = ["系统服务", "数量", "占比"]
    for service_info in statist["service_percent_list"]:
        services.extend([service_info["service_name"], service_info["amount"], service_info["percent"]])
    cnt = 0
    for row in range(5, 27):
        for col in range(6, 9):
            if cnt >= len(services):
                continue
            ws.cell(column=col, row=row, value=services[cnt])
            cnt += 1
    ws["F27"] = "系统服务类别总数"
    ws["F28"] = statist["service_total"]

    product = ["产品", "数量", "占比"]
    for product_info in statist["product_percent_list"]:
        product.extend([product_info["product"], product_info["amount"], product_info["percent"]])
    cnt = 0
    for row in range(5, 27):
        for col in range(11, 14):
            if cnt >= len(product):
                continue
            ws.cell(column=col, row=row, value=product[cnt])
            cnt += 1
    ws["K27"] = "产品类别总数"
    ws["K28"] = statist["product_total"]
    set_sheet_style(ws)

    return save_virtual_workbook(wb)
