// ARL 应用登录账号（arl 库 user 集合，应用层鉴权，不是数据库认证用户）。
// 账号只允许来自 .env 注入的环境变量；缺失直接失败——回退内置弱口令即“默认弱凭据
// 使用路径”，计划 1 治理禁止。compose 层已用 ${VAR:?} 必填拦截，本文件是纵深防御。
const crypto = require('crypto');

function hex_md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

var appUsername = process.env.ARL_APP_USERNAME;
var appPassword = process.env.ARL_APP_PASSWORD;
if (!appUsername || !appPassword) {
    throw new Error('ARL_APP_USERNAME/ARL_APP_PASSWORD must be set (see .env.example); refusing default credentials');
}

// 计算 MD5 哈希
var passwordHash = hex_md5('arlsalt!@#' + appPassword);

// 删除已有的用户数据
db.user.drop();

// 插入新的用户数据
db.user.insert({ username: appUsername, password: passwordHash });

print('User inserted: ' + appUsername);
