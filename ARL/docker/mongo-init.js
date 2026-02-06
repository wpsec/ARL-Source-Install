// db.user.drop()
// db.user.insert({ username: 'admin',  password: hex_md5('arlsalt!@#'+'arlpass') })

// 使用 Node.js 计算 MD5 哈希
const crypto = require('crypto');

// 定义 hex_md5 函数
function hex_md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

// 计算 MD5 哈希
var passwordHash = hex_md5('arlsalt!@#' + 'arlpass');

// 删除已有的用户数据
db.user.drop();

// 插入新的用户数据
db.user.insert({ username: 'admin', password: passwordHash });

print('User inserted with hashed password: ' + passwordHash);
