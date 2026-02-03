#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARL 报告导出 API 测试脚本
"""

import requests
import json
import time
import sys
from typing import Optional

class ARLReportClient:
    def __init__(self, base_url: str, token: str, basic: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.basic = basic
        self.session = requests.Session()
        
        # 设置请求头
        self.session.headers.update({
            'Token': token,
            'Content-Type': 'application/json'
        })
        
        if basic:
            self.session.headers.update({
                'Authorization': f'Basic {basic}'
            })

    def _request(self, method: str, endpoint: str, **kwargs):
        """发送请求"""
        url = f"{self.base_url}/api{endpoint}"
        try:
            resp = self.session.request(method, url, verify=False, timeout=30, **kwargs)
            return resp
        except Exception as e:
            print(f"❌ 请求失败: {e}")
            return None

    def list_tasks(self, page: int = 1, per_page: int = 20):
        """列出所有任务"""
        print(f"获取任务列表 (page={page}, per_page={per_page})...")
        resp = self._request('GET', '/report/tasks', params={
            'page': page,
            'per_page': per_page
        })
        
        if not resp:
            return None
        
        if resp.status_code != 200:
            print(f"❌ 错误: HTTP {resp.status_code}")
            print(f"响应: {resp.text}")
            return None
        
        data = resp.json()
        if data.get('code') == 200:
            tasks = data.get('data', {}).get('items', [])
            total = data.get('data', {}).get('total', 0)
            print(f"✓ 获取成功，总共{total}个任务")
            for task in tasks:
                print(f"  - {task.get('name')} ({task.get('status')})")
            return tasks
        else:
            print(f"❌ API错误: {data.get('message')}")
            return None

    def export_sync(self, task_names: list, merge: bool = True, output_format: str = 'excel'):
        """同步导出报告"""
        print(f"同步导出报告...")
        print(f"  任务: {task_names}")
        print(f"  合并: {merge}")
        print(f"  格式: {output_format}")
        
        resp = self._request('POST', '/report/export', json={
            'task_names': task_names,
            'merge': merge,
            'output_format': output_format
        })
        
        if not resp:
            return None
        
        if resp.status_code == 200:
            # 保存文件
            filename = resp.headers.get('Content-Disposition', 'report.xlsx').split('filename=')[-1].strip('";')
            with open(filename, 'wb') as f:
                f.write(resp.content)
            print(f"✓ 导出成功: {filename}")
            return filename
        else:
            print(f"❌ 导出失败: HTTP {resp.status_code}")
            print(f"响应: {resp.text}")
            return None

    def export_async(self, task_names: list, merge: bool = True, output_format: str = 'excel'):
        """异步导出报告"""
        print(f"异步导出报告...")
        print(f"  任务: {task_names}")
        print(f"  合并: {merge}")
        print(f"  格式: {output_format}")
        
        resp = self._request('POST', '/report/export-async', json={
            'task_names': task_names,
            'merge': merge,
            'output_format': output_format
        })
        
        if not resp:
            return None
        
        if resp.status_code != 200:
            print(f"❌ 提交失败: HTTP {resp.status_code}")
            print(f"响应: {resp.text}")
            return None
        
        data = resp.json()
        if data.get('code') == 200:
            job_id = data.get('data', {}).get('job_id')
            print(f"✓ 任务已提交，job_id: {job_id}")
            return job_id
        else:
            print(f"❌ API错误: {data.get('message')}")
            return None

    def get_export_status(self, job_id: str):
        """查询导出状态"""
        resp = self._request('GET', f'/report/export-status/{job_id}')
        
        if not resp:
            return None
        
        if resp.status_code != 200:
            print(f"❌ 查询失败: HTTP {resp.status_code}")
            return None
        
        data = resp.json()
        if data.get('code') == 200:
            status_data = data.get('data', {})
            status = status_data.get('status')
            print(f"状态: {status}")
            
            if status == 'SUCCESS':
                print(f"✓ 导出完成")
                print(f"  文件名: {status_data.get('filename')}")
                print(f"  下载链接: {status_data.get('download_url')}")
            elif status == 'FAILURE':
                print(f"❌ 导出失败: {status_data.get('error')}")
            
            return status_data
        else:
            print(f"❌ API错误: {data.get('message')}")
            return None

    def download_report(self, job_id: str, output_file: Optional[str] = None):
        """下载报告文件"""
        print(f"下载报告 (job_id={job_id})...")
        
        resp = self._request('GET', f'/report/download/{job_id}')
        
        if not resp:
            return None
        
        if resp.status_code == 200:
            if not output_file:
                output_file = resp.headers.get('Content-Disposition', 'report.xlsx').split('filename=')[-1].strip('";')
            
            with open(output_file, 'wb') as f:
                f.write(resp.content)
            
            print(f"✓ 下载成功: {output_file}")
            return output_file
        else:
            print(f"❌ 下载失败: HTTP {resp.status_code}")
            return None


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='ARL 报告导出 API 测试工具')
    parser.add_argument('--url', required=True, help='ARL服务器地址，如 https://localhost:5003')
    parser.add_argument('--token', required=True, help='API Token')
    parser.add_argument('--basic', help='Basic认证字符串 (可选)')
    
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # list-tasks 命令
    subparsers.add_parser('list-tasks', help='列出所有任务')
    
    # export 命令
    export_parser = subparsers.add_parser('export', help='同步导出报告')
    export_parser.add_argument('task_names', nargs='+', help='任务名称列表')
    export_parser.add_argument('--merge', action='store_true', default=True, help='合并报告')
    export_parser.add_argument('--format', choices=['excel', 'json'], default='excel', help='输出格式')
    
    # export-async 命令
    export_async_parser = subparsers.add_parser('export-async', help='异步导出报告')
    export_async_parser.add_argument('task_names', nargs='+', help='任务名称列表')
    export_async_parser.add_argument('--merge', action='store_true', default=True, help='合并报告')
    export_async_parser.add_argument('--wait', action='store_true', help='等待完成后下载')
    export_async_parser.add_argument('--format', choices=['excel', 'json'], default='excel', help='输出格式')
    
    # status 命令
    status_parser = subparsers.add_parser('status', help='查询导出状态')
    status_parser.add_argument('job_id', help='任务ID')
    
    # download 命令
    download_parser = subparsers.add_parser('download', help='下载报告')
    download_parser.add_argument('job_id', help='任务ID')
    download_parser.add_argument('--output', help='输出文件名')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # 创建客户端
    client = ARLReportClient(args.url, args.token, args.basic)
    
    # 禁用SSL警告（仅用于测试）
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 执行命令
    if args.command == 'list-tasks':
        client.list_tasks()
    
    elif args.command == 'export':
        client.export_sync(args.task_names, merge=args.merge, output_format=args.format)
    
    elif args.command == 'export-async':
        job_id = client.export_async(args.task_names, merge=args.merge, output_format=args.format)
        
        if job_id and args.wait:
            print("\n等待导出完成...")
            while True:
                time.sleep(2)
                status = client.get_export_status(job_id)
                if status and status.get('status') in ['SUCCESS', 'FAILURE']:
                    break
            
            if status and status.get('status') == 'SUCCESS':
                client.download_report(job_id)
    
    elif args.command == 'status':
        client.get_export_status(args.job_id)
    
    elif args.command == 'download':
        client.download_report(args.job_id, args.output)


if __name__ == '__main__':
    main()
