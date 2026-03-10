// db.user.drop()
// db.user.insert({ username: 'admin',  password: hex_md5('arlsalt!@#'+'arlpass') })

// 使用 Node.js 计算 MD5 哈希
const crypto = require('crypto');

// 定义 hex_md5 函数
function hex_md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

// 从环境变量读取 ARL 应用账号（未设置则回退默认值）
var appUsername = process.env.ARL_APP_USERNAME || 'admin';
var appPassword = process.env.ARL_APP_PASSWORD || 'arlpass';

// 计算 MD5 哈希
var passwordHash = hex_md5('arlsalt!@#' + appPassword);

// 删除已有的用户数据
db.user.drop();

// 插入新的用户数据
db.user.insert({ username: appUsername, password: passwordHash });

print('User inserted: ' + appUsername);
