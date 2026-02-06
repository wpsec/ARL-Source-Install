"""
消息推送通知模块

功能说明：
- 支持邮件推送
- 支持钉钉推送
- 用于任务结果通知和监控告警
"""
from app.config import Config
from app.utils import get_logger, push

logger = get_logger()


def push_email(title, html_report):
    """
    发送邮件通知
    
    参数：
        title: 邮件标题
        html_report: HTML格式的报告内容
    
    返回：
        bool: True-发送成功，None-发送失败
    
    说明：
    - 需要在配置中设置EMAIL_HOST、EMAIL_USERNAME、EMAIL_PASSWORD
    - 收件人地址在EMAIL_TO中配置
    - 支持HTML格式的富文本邮件
    - 用于GitHub搜索、资产监控等结果通知
    """
    try:
        if Config.EMAIL_HOST and Config.EMAIL_USERNAME and Config.EMAIL_PASSWORD:
            push.send_email(host=Config.EMAIL_HOST, port=Config.EMAIL_PORT, mail=Config.EMAIL_USERNAME,
                            password=Config.EMAIL_PASSWORD, to=Config.EMAIL_TO,
                            title=title, html=html_report)
            logger.info("send email succ")
            return True
    except Exception as e:
        logger.info("error on send email {}".format(title))
        logger.warning(e)


def push_dingding(markdown_report):
    """
    发送钉钉通知
    
    参数：
        markdown_report: Markdown格式的报告内容
    
    返回：
        bool: True-发送成功，None-发送失败
    
    说明：
    - 需要在配置中设置DINGDING_ACCESS_TOKEN和DINGDING_SECRET
    - 使用钉钉机器人Webhook推送
    - 支持Markdown格式的消息
    - 返回errcode为0表示成功
    - 适合移动端查看
    """
    try:
        if Config.DINGDING_ACCESS_TOKEN and Config.DINGDING_SECRET:
            data = push.dingding_send(access_token=Config.DINGDING_ACCESS_TOKEN,
                                      secret=Config.DINGDING_SECRET, msgtype="markdown",
                                      msg=markdown_report)
            if data.get("errcode", -1) == 0:
                logger.info("push dingding succ")
                return True
            else:
                logger.info("{}".format(data))

    except Exception as e:
        logger.info("error on send dingding {}".format(markdown_report[:15]))
        logger.warning(e)



