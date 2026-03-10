#!/bin/bash

# ARL MongoDB 容器名
CONTAINER_NAME="arl_mongodb"
MONGO_ROOT_PASS="admin"

echo "[*] 正在尝试通过身份验证重置 ARL 管理员密码..."

# 使用 -u 和 -p 进行认证
docker exec -i $CONTAINER_NAME mongosh -u admin -p "$MONGO_ROOT_PASS" --authenticationDatabase admin arl --eval "
  // 1. 定义 MD5 函数以兼容 mongosh
  const hex_md5 = (str) => crypto.createHash('md5').update(str).digest('hex');
  
  const salt = 'arlsalt!@#';
  const new_pass = 'admin123';
  const hashed_pass = hex_md5(salt + new_pass);

  // 2. 这里的权限现在应该足够了
  db.user.drop();
  db.user.insertOne({
    username: 'admin',
    password: hashed_pass
  });

  print('[+] 密码已重置为: admin123');
"