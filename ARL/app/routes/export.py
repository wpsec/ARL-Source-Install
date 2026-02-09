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
from collections import Counter
from openpyxl.writer.excel import save_virtual_workbook
from openpyxl.styles import Font, Color
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
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


def set_sheet_style(ws):
    """
    统一设置工作表字体样式（与单任务导出保持一致）
    """
    font = Font(name="Consolas", color="111111")
    column = "ABCDEFGHIJKLMNO"
    for x in column:
        for y in range(1, 256):
            ws["{}{}".format(x, y)].font = font


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
        font = Font(name="Consolas", color="111111")
        column = "ABCDEFGHIJKLMNO"
        for x in column:
            for y in range(1, 256):
                ws["{}{}".format(x,y)].font = font

    def build_service_xl(self):
        ws = self.wb.create_sheet(title="系统服务")
        ws.column_dimensions['A'].width = 22.0
        ws.column_dimensions['B'].width = 10.0
        ws.column_dimensions['C'].width = 20.0
        ws.column_dimensions['D'].width = 40.0

        column_tilte = ["IP", "端口","服务", "产品", "版本"]
        ws.append(column_tilte)
        for item in get_ip_data(self.task_id):
            for port_info in item["port_info"]:
                row = []
                row.append(item["ip"])
                row.append("{}".format(port_info["port_id"]))
                row.append(port_info["service_name"])
                row.append(port_info.get("product", ""))
                row.append(port_info.get("version", ""))
                ws.append(row)

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
        if not self.is_ip_task:
            self.build_domain_xl()

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
    - 自动去重IP、域名、站点等数据
    """
    wb = Workbook()
    if 'Sheet' in wb.sheetnames:
        wb.remove(wb['Sheet'])

    valid_tasks = []
    for task_id in task_id_list:
        if not task_id:
            continue
        task_data = get_task_data(task_id)
        if task_data:
            valid_tasks.append(task_data)

    if not valid_tasks:
        raise ValueError("未找到可导出的任务数据")

    # 与单任务保持一致：仅当全部任务都是 IP 类型时，按 IP 任务列导出；否则按通用任务列导出
    is_ip_task = True
    for task_data in valid_tasks:
        target = sanitize_excel_value(task_data.get("target", ""))
        if not (re.findall(r"\b\d+\.\d+\.\d+\.\d+", target) or task_data.get("type", "") == "ip"):
            is_ip_task = False
            break

    merged_ips = {}       # key: ip, value: ip文档
    merged_domains = {}   # key: domain
    merged_sites = {}     # key: site

    for task_data in valid_tasks:
        task_id = str(task_data.get("_id"))

        for ip_item in get_ip_data(task_id):
            ip = ip_item.get("ip")
            if not ip:
                continue

            if ip not in merged_ips:
                merged_ips[ip] = {
                    "ip": ip,
                    "port_info": [],
                    "geo_city": ip_item.get("geo_city", {}),
                    "geo_asn": ip_item.get("geo_asn", {}),
                    "domain": as_list(ip_item.get("domain", [])),
                    "os_info": ip_item.get("os_info", {}),
                    "cdn_name": ip_item.get("cdn_name", ""),
                    "ip_type": ip_item.get("ip_type", ""),
                }

            current = merged_ips[ip]
            if not current.get("geo_city") and ip_item.get("geo_city"):
                current["geo_city"] = ip_item.get("geo_city", {})
            if not current.get("geo_asn") and ip_item.get("geo_asn"):
                current["geo_asn"] = ip_item.get("geo_asn", {})
            if not current.get("os_info") and ip_item.get("os_info"):
                current["os_info"] = ip_item.get("os_info", {})
            if not current.get("cdn_name") and ip_item.get("cdn_name"):
                current["cdn_name"] = ip_item.get("cdn_name", "")
            if not current.get("ip_type") and ip_item.get("ip_type"):
                current["ip_type"] = ip_item.get("ip_type", "")

            merged_domain_set = set(current.get("domain", []))
            merged_domain_set.update(as_list(ip_item.get("domain", [])))
            current["domain"] = sorted([d for d in merged_domain_set if d])

            existed_port_keys = set()
            for port_info in current.get("port_info", []):
                existed_port_keys.add((
                    port_info.get("port_id"),
                    port_info.get("service_name"),
                    port_info.get("product"),
                    port_info.get("version")
                ))

            for port_info in as_list(ip_item.get("port_info", [])):
                if not isinstance(port_info, dict):
                    continue
                key = (
                    port_info.get("port_id"),
                    port_info.get("service_name"),
                    port_info.get("product"),
                    port_info.get("version")
                )
                if key not in existed_port_keys:
                    current["port_info"].append(port_info)
                    existed_port_keys.add(key)

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

    if not merged_ips and not merged_domains and not merged_sites:
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

    merged_ip_items = [merged_ips[ip] for ip in sorted(merged_ips.keys())]
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
    for item in merged_ip_items:
        for port_info in item.get("port_info", []):
            ws.append([
                sanitize_excel_value(item.get("ip", "")),
                sanitize_excel_value(port_info.get("port_id", "")),
                sanitize_excel_value(port_info.get("service_name", "")),
                sanitize_excel_value(port_info.get("product", "")),
                sanitize_excel_value(port_info.get("version", "")),
            ])
    set_sheet_style(ws)

    # 域名（与单任务导出同结构，非IP任务时输出）
    if not is_ip_task:
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
