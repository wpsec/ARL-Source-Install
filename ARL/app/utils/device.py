"""
设备信息获取和系统监控
"""
import psutil


def device_info():
    ret = dict()
    ret["cpu"] = {
        "count": psutil.cpu_count(),
        "percent": psutil.cpu_percent()
    }

    v_mem = psutil.virtual_memory()
    memory_info = {
        "total": human_size(v_mem.total),
        "used": human_size(v_mem.total - v_mem.available),
        "percent": v_mem.percent
    }
    # 兼容新旧前端字段命名
    ret["virtual_memory"] = memory_info
    ret["memory"] = memory_info

    disk = psutil.disk_usage("/")
    disk_info = {
        "total": human_size(disk.total),
        "used": human_size(disk.used),
        "percent": disk.percent
    }
    # 兼容新旧前端字段命名
    ret["disk_usage"] = disk_info
    ret["disk"] = disk_info
    return ret


def human_size(byte):
    for x in ["", "K", "M", "G", "T"]:
        if byte < 1024:
            return f"{byte:.2f}{x}"
        byte = byte/1024
