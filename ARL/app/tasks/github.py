"""
GitHub敏感信息搜索任务模块

功能说明：
- 在GitHub上搜索指定关键词，发现敏感信息泄露
- 支持一次性任务和定期监控任务

主要功能：
1. GitHub搜索：根据关键词搜索代码、提交记录
2. 内容获取：获取搜索结果的完整内容
3. 结果过滤：过滤误报和无关结果
4. 监控任务：定期搜索并推送新发现
5. 消息推送：邮件、钉钉通知

主要类：
- GithubTaskTask: GitHub普通任务（一次性搜索）
- GithubTaskMonitor: GitHub监控任务（定期搜索）

执行流程：
普通任务：1. 搜索 -> 2. 获取内容 -> 3. 过滤 -> 4. 保存结果 -> 5. 统计
监控任务：1. 初始化MD5 -> 2. 搜索 -> 3. 去重 -> 4. 保存 -> 5. 推送通知

说明：
- 需要配置GITHUB_TOKEN才能使用
- 监控任务通过MD5去重避免重复推送
- 支持关键词高亮显示
"""
from bson import ObjectId
from app.services import github_search
from app.services.githubSearch import GithubResult
from app.modules import TaskStatus
from app import utils
from app.config import Config
from app.utils import push

logger = utils.get_logger()


class GithubTaskTask(object):
    """
    GitHub普通任务类
    
    功能说明：
    - 一次性搜索任务
    - 根据关键词搜索GitHub代码
    - 保存搜索结果到数据库
    
    主要属性：
    - task_id: 任务ID
    - keyword: 搜索关键词
    - results: 搜索结果列表
    
    主要方法：
    - search_result(): 执行搜索
    - save_content(): 保存内容
    - filter_result(): 过滤结果
    """
    
    def __init__(self, task_id, keyword):
        """
        初始化GitHub任务
        
        参数：
            task_id: 任务ID
            keyword: 搜索关键词（如：域名、邮箱、API密钥等）
        """
        self.task_id = task_id
        self.keyword = keyword
        self.collection = "github_task"
        self.results = []

    def search_result(self):
        """
        执行GitHub搜索
        
        说明：
        - 调用GitHub API搜索代码
        - 搜索范围：代码文件、提交记录、Issue等
        - 返回包含关键词的文件和行号
        """
        self.update_status("search")
        results = github_search(keyword=self.keyword)
        self.results.extend(results)

    def save_content(self):
        """
        保存搜索结果内容
        
        说明：
        - 遍历所有搜索结果
        - 过滤无关结果
        - 保存到github_result表
        - 包含关键词高亮信息
        """
        self.update_status("fetch content-{}".format(len(self.results)))
        for result in self.results:
            if not isinstance(result, GithubResult):
                continue

            # 过滤结果
            if self.filter_result(result):
                continue

            item = self.result_to_dict(result)

            utils.conn_db("github_result").insert_one(item)

    def result_to_dict(self, result):
        """
        转换结果为字典格式
        
        参数：
            result: GithubResult对象
        
        返回：
            dict: 包含所有信息的字典
        
        说明：
        - 转换为数据库存储格式
        - 添加关键词高亮的内容
        - 关联任务ID和关键词
        """
        item = result.to_dict()
        item["human_content"] = result.human_content(self.keyword)
        item["keyword"] = self.keyword
        item["github_task_id"] = self.task_id
        return item

    def filter_result(self, result: GithubResult):
        """
        过滤搜索结果
        
        参数：
            result: GithubResult对象
        
        返回：
            bool: True=过滤掉，False=保留
        
        说明：
        - 过滤路径黑名单：广告过滤规则、爬虫配置等
        - 过滤内容黑名单：域名列表、Android代码模板等
        - 减少误报，提高结果质量
        """
        # 路径黑名单
        path_keyword_list = ["open-app-filter/", "/adbyby",
                             "/adblock", "luci-app-dnsfilter/",
                             "Spider/", "/spider", "_files/",
                             "alexa_10k.json", "/WeWorkProviderTest.php"]
        for path in path_keyword_list:
            if path in result.path:
                return True

        # 内容黑名单
        content_keyword_list = ["DOMAIN-SUFFIX", "HOST-SUFFIX", "name:[proto;sport;dport;host",
                                '  "websites": [',
                                "import android.app.Application;",
                                "import android.app.Activity;"]
        for keyword in content_keyword_list:
            if keyword in result.content:
                return True

        return False

    def update_status(self, value):
        """更新任务状态"""
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {"status": value}}
        utils.conn_db(self.collection).update_one(query, update)

    def set_start_time(self):
        """设置任务开始时间"""
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {"start_time": utils.curr_date()}}
        utils.conn_db(self.collection).update_one(query, update)

    def set_end_time(self):
        """设置任务结束时间"""
        query = {"_id": ObjectId(self.task_id)}
        update = {"$set": {"end_time": utils.curr_date()}}
        utils.conn_db(self.collection).update_one(query, update)

    def statistic(self):
        """
        生成任务统计信息
        
        说明：
        - 统计github_result表中的记录数
        - 更新到任务的statistic字段
        """
        query = {"_id": ObjectId(self.task_id)}
        table_list = ['github_result']
        result = {}
        for table in table_list:
            cnt = utils.conn_db(table).count_documents({"github_task_id": self.task_id})
            stat_key = table + "_cnt"
            result[stat_key] = cnt

        logger.info("insert task stat")
        update = {"$set": {"statistic": result}}
        utils.conn_db(self.collection).update_one(query, update)

    def run(self):
        """
        执行GitHub任务
        
        执行流程：
        1. 记录开始时间
        2. 执行搜索
        3. 保存内容
        4. 更新状态为完成
        5. 生成统计信息
        6. 记录结束时间
        """
        self.set_start_time()

        self.search_result()
        self.save_content()

        self.update_status(TaskStatus.DONE)
        self.statistic()
        self.set_end_time()


class GithubTaskMonitor(GithubTaskTask):
    """
    GitHub监控任务类
    
    功能说明：
    - 定期监控GitHub敏感信息
    - 自动去重，只推送新发现
    - 支持邮件和钉钉通知
    
    继承自：
    - GithubTaskTask: 复用搜索和保存功能
    
    主要属性：
    - scheduler_id: 调度器ID
    - hash_md5_list: 已处理结果的MD5列表（去重）
    - new_results: 新发现的结果列表
    
    主要方法：
    - init_md5_list(): 初始化MD5列表
    - save_mongo(): 保存监控结果
    - build_html_report(): 构建HTML报告
    - build_markdown_report(): 构建Markdown报告
    - push_msg(): 推送消息通知
    """
    
    def __init__(self, task_id, keyword, scheduler_id):
        """
        初始化GitHub监控任务
        
        参数：
            task_id: 任务ID
            keyword: 搜索关键词
            scheduler_id: 调度器ID
        """
        super().__init__(task_id, keyword)
        self.scheduler_id = scheduler_id
        self.hash_md5_list = []  # MD5列表（去重）
        self.new_results = []  # 新发现的结果

    def init_md5_list(self):
        """
        初始化MD5列表
        
        说明：
        - 从github_hash表加载已处理结果的MD5
        - 用于去重，避免重复推送
        - 按调度器ID分组管理
        """
        query = {"github_scheduler_id": self.scheduler_id}
        results = list(utils.conn_db("github_hash").find(query, {"hash_md5": 1}))
        for result in results:
            if result["hash_md5"] not in self.hash_md5_list:
                self.hash_md5_list.append(result["hash_md5"])

    def save_mongo(self):
        """
        保存监控结果到数据库
        
        说明：
        - 遍历搜索结果
        - 通过MD5去重，跳过已处理的结果
        - 保存新MD5到github_hash表
        - 过滤无关结果
        - 保存到github_monitor_result表
        - new_results记录新发现，用于推送通知
        """
        cnt = 0
        self.update_status("fetch content")
        for result in self.results:
            if not isinstance(result, GithubResult):
                continue

            # MD5去重
            if result.hash_md5 in self.hash_md5_list:
                continue

            # 保存MD5，避免重复处理（在过滤前保存）
            self.hash_md5_list.append(result.hash_md5)
            hash_data = {"hash_md5": result.hash_md5, "github_scheduler_id": self.scheduler_id}
            utils.conn_db("github_hash").insert_one(hash_data)

            # 过滤无关结果
            if self.filter_result(result):
                continue

            # 保存监控结果
            item = self.result_to_dict(result)
            item["github_scheduler_id"] = self.scheduler_id
            item["update_date"] = utils.curr_date_obj()
            cnt += 1
            self.new_results.append(result)
            utils.conn_db("github_monitor_result").insert_one(item)

        logger.info("github_monitor save {} {}".format(self.keyword, cnt))

    def build_repo_map(self):
        """
        构建仓库映射
        
        返回：
            dict: {仓库名: [结果列表]}
        
        说明：
        - 按仓库分组结果
        - 用于生成报告时按仓库展示
        """
        repo_map = dict()
        for result in self.new_results:
            repo_name = result.repo_full_name
            if repo_map.get(repo_name) is None:
                repo_map[repo_name] = [result]
            else:
                repo_map[repo_name].append(result)

        return repo_map

    def build_html_report(self):
        """
        构建HTML格式报告
        
        返回：
            str: HTML格式的报告内容
        
        说明：
        - 用于邮件推送
        - 包含仓库统计、文件列表、代码片段
        - 最多显示5个仓库，每个仓库最多10个结果
        - 关键词高亮显示
        - 代码内容限制2000字符
        """
        repo_map = self.build_repo_map()
        repo_cnt = 0
        html = "<br/><br/> <div> 搜索: {}  仓库数：{}  结果数： {} </div>".format(self.keyword,
                                                                        len(repo_map.keys()), len(self.new_results))
        for repo_name in repo_map:
            repo_cnt += 1
            # 为了减少长度，超过5个仓库就跳过
            if repo_cnt > 5:
                break

            start_div = '<br/><br/><br/><div>#{} <a href="https://github.com/{}"> {} </a> 结果数：{}</div><br/>\n'.format(
                repo_cnt, repo_name, repo_name, len(repo_map[repo_name]))
            table_start = '''<table style="border-collapse: collapse;">
            <thead>
                <tr>
                    <th style="border: 0.5pt solid; padding:14px;">编号</th>
                    <th style="border: 0.5pt solid; padding:14px;">文件名</th>
                    <th style="border: 0.5pt solid; padding:14px;">代码</th>
                    <th style="border: 0.5pt solid; padding:14px;">Commit 时间</th>
                </tr>
            </thead>
            <tbody>\n'''
            html += start_div
            html += table_start

            style = 'style="border: 0.5pt solid; font-size: 14px; padding:14px"'
            tr_cnt = 0
            for item in repo_map[repo_name]:
                tr_cnt += 1
                code_content = item.human_content(self.keyword).replace('>', "&#x3e;").replace('<', "&#x3c;")
                code_content = code_content[:2000]
                tr_tag = '<tr>' \
                         '<td {}> {} </td>' \
                         '<td {}> <div style="width: 300px"> <a href="{}"> {} </a> </div> </td>' \
                         '<td {}> <pre style="max-width: 600px; overflow: auto; max-height: 600px;">{}</pre></td>' \
                         '<td {}> {} </td>' \
                         '</tr>\n'.format(
                    style, tr_cnt, style, item.html_url, item.path,
                    style, code_content,
                    style, item.commit_date)

                html += tr_tag
                if tr_cnt > 10:
                    break

            table_end = '</tbody></table>'
            end_div = "</div>"

            html += table_end
            html += end_div

        return html

    def build_markdown_report(self):
        """
        构建Markdown格式报告
        
        返回：
            str: Markdown格式的报告内容
        
        说明：
        - 用于钉钉推送
        - 包含仓库统计和文件链接列表
        - 最多显示5个仓库，每个仓库最多5个结果
        - 简洁格式，适合移动端查看
        """
        repo_map = self.build_repo_map()

        markdown = "### GitHub 监控结果\n\n"
        markdown += "- 关键词：`{}`\n".format(self.keyword)
        markdown += "- 仓库数：`{}`\n".format(len(repo_map.keys()))
        markdown += "- 新增结果：`{}`\n\n".format(len(self.new_results))
        markdown += "#### 结果列表\n\n"

        global_cnt = 0
        repo_cnt = 0
        for repo_name in repo_map:
            repo_cnt += 1
            # 为了减少长度，超过5个仓库就跳过
            if repo_cnt > 5:
                break

            tr_cnt = 0
            for item in repo_map[repo_name]:
                tr_cnt += 1
                global_cnt += 1
                url_text = item.repo_full_name + " " + item.path
                markdown += "{}. [{}]({})\n".format(global_cnt, url_text, item.html_url)
                if tr_cnt > 5:
                    break

        return markdown

    def push_msg(self):
        """
        推送消息通知
        
        说明：
<<<<<<< HEAD
        - 仅在有新增结果时推送（钉钉/邮件）
=======
        - 只有发现新结果才推送
        - 同时推送钉钉和邮件
>>>>>>> 2206ccf2c4fd7a50bd4600ba24497329f627c06b
        - 失败不影响任务执行
        """
        if not self.new_results:
            return

        logger.info("found new result {} {}".format(self.keyword, len(self.new_results)))
        if self.enable_dingding_notify():
            self.push_dingding()
        self.push_email()

    def enable_dingding_notify(self):
        """
        是否启用 GitHub 监控钉钉通知

        说明：
        - 读取 github_scheduler 配置项 dingding_notify
        - 兼容历史数据：字段缺失时默认启用
        """
        try:
            if not self.scheduler_id or len(self.scheduler_id) != 24:
                return True

            query = {"_id": ObjectId(self.scheduler_id)}
            item = utils.conn_db("github_scheduler").find_one(query, {"dingding_notify": 1})
            if not item:
                return True

            dingding_notify_value = item.get("dingding_notify", None)
            if dingding_notify_value is None:
                return True

            return bool(dingding_notify_value)
        except Exception:
            return True

    def push_dingding(self):
        """
        推送钉钉通知
        
        返回：
            bool: 推送是否成功
        
        说明：
        - 需要配置DINGDING_ACCESS_TOKEN和DINGDING_SECRET
        - 使用Markdown格式
        - 推送失败不抛异常
        """
        try:
            if Config.DINGDING_ACCESS_TOKEN and Config.DINGDING_SECRET:
                data = push.dingding_send(access_token=Config.DINGDING_ACCESS_TOKEN,
                                      secret=Config.DINGDING_SECRET, msgtype="markdown",
                                      msg=self.build_markdown_report())
                if data.get("errcode", -1) == 0:
                    logger.info("push dingding succ")
                return True

        except Exception as e:
            logger.warning(self.keyword, e)

    def push_email(self):
        """
        推送邮件通知
        
        返回：
            bool: 推送是否成功
        
        说明：
        - 需要配置EMAIL相关参数
        - 使用HTML格式
        - 推送失败不抛异常
        """
        try:
            if Config.EMAIL_HOST and Config.EMAIL_USERNAME and Config.EMAIL_PASSWORD:
                html_report = self.build_html_report()
                push.send_email(host=Config.EMAIL_HOST, port=Config.EMAIL_PORT, mail=Config.EMAIL_USERNAME,
                                password=Config.EMAIL_PASSWORD, to=Config.EMAIL_TO,
                                title="[Github--{}] 灯塔消息推送".format(self.keyword), html=html_report)
                logger.info("send email succ")
                return True
        except Exception as e:
            logger.warning(self.keyword, e)

    def run(self):
        """
        执行GitHub监控任务
        
        执行流程：
        1. 记录开始时间
        2. 初始化MD5列表（去重）
        3. 执行搜索
        4. 保存监控结果（去重后的新结果）
        5. 保存任务结果
        6. 推送消息通知
        7. 生成统计信息
        8. 更新状态为完成
        9. 记录结束时间
        """
        self.set_start_time()

        # 初始化MD5
        self.init_md5_list()

        # 根据关键字搜索出结果
        self.search_result()

        # 保存到监控结果
        self.save_mongo()

        # 保存到任务结果
        self.results = self.new_results
        self.save_content()

        # 推送消息
        self.push_msg()

        # 保存统计结果
        self.statistic()
        self.update_status(TaskStatus.DONE)
        self.set_end_time()


def github_task_task(task_id, keyword):
    """
    GitHub普通任务入口
    
    参数：
        task_id: 任务ID
        keyword: 搜索关键词
    
    说明：
    - 一次性搜索任务
    - 需要配置GITHUB_TOKEN
    - 捕获异常并标记任务状态
    """
    task = GithubTaskTask(task_id=task_id, keyword=keyword)
    try:
        if not Config.GITHUB_TOKEN:
            logger.error("GITHUB_TOKEN is empty")
            task.update_status(TaskStatus.ERROR)
            task.set_end_time()
            return

        task.run()
    except Exception as e:
        logger.exception(e)

        task.update_status(TaskStatus.ERROR)
        task.set_end_time()


def github_task_monitor(task_id, keyword, scheduler_id):
    """
    GitHub监控任务入口
    
    参数：
        task_id: 任务ID
        keyword: 搜索关键词
        scheduler_id: 调度器ID
    
    说明：
    - 定期监控任务
    - 自动去重和推送
    - 捕获异常并标记任务状态
    """
    task = GithubTaskMonitor(task_id=task_id,
                             keyword=keyword, scheduler_id=scheduler_id)
    try:
        task.run()
    except Exception as e:
        logger.exception(e)

        task.update_status(TaskStatus.ERROR)
        task.set_end_time()

