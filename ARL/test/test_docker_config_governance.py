"""计划 1 运行时配置治理的离线回归测试。

覆盖四类可复核证据（全部离线，无网络/无容器副作用）：
1. 弱凭据使用路径清零：compose 模板、配置模板、mongo-init.js、start.sh、.env.example；
2. 凭据 env 注入链：inject_url_credentials 纯函数 + 子进程端到端（不污染本进程 app.* 槽位）；
3. 诊断不污染 stdout：import app.config 的 stdout 必须为空（gunicorn/celery 参数防灌）；
4. 启动前必填检查：check-deploy-env.sh fixture 正负例 + docker compose config 负例（无 docker 时 skip）；
5. 首次安装凭据初始化：init-deploy-env.sh 自动生成/幂等/用户项边界/600 权限/预检联动。

卫生约定：不在本进程 monkeypatch os.environ / app.config 槽位；涉及环境变量的行为
断言全部走 subprocess，结束后无残留。
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
try:
    from test._layout import PROJECT_ROOT
except ImportError:
    from _layout import PROJECT_ROOT

REPO_ROOT = PROJECT_ROOT
ARL_ROOT = REPO_ROOT / "ARL"
DOCKER_DIR = ARL_ROOT / "docker"
COMPOSE_FILE = DOCKER_DIR / "docker-compose.yml"
ENV_EXAMPLE_DOCKER = DOCKER_DIR / ".env.example"
ENV_EXAMPLE_ROOT = REPO_ROOT / ".env.example"
CHECK_SCRIPT = DOCKER_DIR / "check-deploy-env.sh"

# 与 check-deploy-env.sh / docker-compose.yml `:?` 语义对齐的必填键。
REQUIRED_ENV_KEYS = (
    "MONGO_INITDB_ROOT_USERNAME",
    "MONGO_INITDB_ROOT_PASSWORD",
    "ARL_APP_USERNAME",
    "ARL_APP_PASSWORD",
    "RABBITMQ_DEFAULT_USER",
    "RABBITMQ_DEFAULT_PASS",
    "BASIC_AUTH_PASSWORD",
)
PASSWORD_KEYS = (
    "MONGO_INITDB_ROOT_PASSWORD",
    "ARL_APP_PASSWORD",
    "RABBITMQ_DEFAULT_PASS",
    "BASIC_AUTH_PASSWORD",
)
# 曾经随仓库分发的默认值：任何入库样例/脚本再出现即治理回归。
LEGACY_WEAK_SECRETS = ("admin123456", "arlpass", "arlpassword")

# 凭据注入 fixture 专用值（非真实凭据；含特殊字符验证 percent-encoding）。
FIXTURE_MONGO_PASS = "P@ss w:0rd#1"
FIXTURE_AMQP_PASS = "Rb#t 7mq/x"


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_env_example(path: pathlib.Path) -> dict:
    """解析 KEY=VALUE 行（忽略注释），返回键值映射。"""
    result = {}
    for line in read(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        result[key.strip()] = value.strip()
    return result


class TestWeakCredentialPathsRemoved(unittest.TestCase):
    """弱凭据使用路径：模板/脚本/样例中不得再出现可用的默认凭据。"""

    def test_compose_template_has_no_embedded_credentials(self):
        import yaml

        doc = yaml.safe_load(read(DOCKER_DIR / "config-docker.yaml"))
        # 模板层连接串不得携带 user:pass@ 凭据段（凭据只允许经 env 注入）。
        uri = doc["MONGO"]["URI"]
        broker = doc["CELERY"]["BROKER_URL"]
        cred_pattern = re.compile(r"://[^\s/@]*:[^\s/@]*@")
        self.assertIsNone(cred_pattern.search(uri), "config-docker.yaml MONGO.URI 不应内嵌凭据")
        self.assertIsNone(cred_pattern.search(broker), "config-docker.yaml BROKER_URL 不应内嵌凭据")
        for weak in LEGACY_WEAK_SECRETS:
            self.assertNotIn(weak, read(DOCKER_DIR / "config-docker.yaml"))

    def test_mongo_init_rejects_missing_env_without_fallback(self):
        content = read(DOCKER_DIR / "mongo-init.js")
        self.assertNotIn("|| 'admin'", content)
        self.assertNotIn("|| 'arlpass'", content)
        self.assertIn("throw new Error", content)

    def test_start_script_has_no_default_credentials_or_echo(self):
        content = read(REPO_ROOT / "start.sh")
        for weak in LEGACY_WEAK_SECRETS:
            self.assertNotIn(weak, content, f"start.sh 不得再内置弱凭据: {weak}")
        # 密码值不得出现在任何回显中（只允许提示去 .env 查看）。
        self.assertNotIn("$BASIC_AUTH_PASS", content)
        self.assertNotIn("${BASIC_AUTH_PASS", content)
        self.assertNotIn("$ARL_APP_PASS", content)
        self.assertNotIn("${ARL_APP_PASS", content)
        self.assertIn("check-deploy-env.sh", content, "start.sh 必须接入 .env 预检")

    def test_resetpass_script_has_no_hardcoded_credentials(self):
        content = read(REPO_ROOT / "resetpass.sh")
        # 历史版本硬编码 root 口令与目标密码；治理后只允许 env/交互隐式输入来源。
        self.assertNotIn('MONGO_ROOT_PASS="admin"', content)
        self.assertNotIn("new_pass = '", content)
        self.assertIn("read -r -s", content)

    def test_env_examples_use_placeholders_for_secrets(self):
        for path in (ENV_EXAMPLE_ROOT, ENV_EXAMPLE_DOCKER):
            parsed = parse_env_example(path)
            missing = [key for key in REQUIRED_ENV_KEYS if key not in parsed]
            self.assertEqual(missing, [], f"{path.name} 缺少必填键: {missing}")
            for key in PASSWORD_KEYS:
                if key in parsed:
                    self.assertEqual(parsed[key], "<set-me>", f"{path.name}:{key} 必须为占位符")
            for weak in LEGACY_WEAK_SECRETS:
                self.assertNotIn(weak, read(path))

    def test_compose_passes_credentials_to_app_services(self):
        import yaml

        doc = yaml.safe_load(read(COMPOSE_FILE))
        for service in ("web", "worker_1", "worker_2", "scheduler"):
            env_keys = {
                item.split("=", 1)[0]
                for item in doc["services"][service]["environment"]
            }
            for key in (
                "MONGO_INITDB_ROOT_USERNAME",
                "MONGO_INITDB_ROOT_PASSWORD",
                "RABBITMQ_DEFAULT_USER",
                "RABBITMQ_DEFAULT_PASS",
                "ARL_API_UNIFIED_ENABLE",
                "ARL_API_UNIFIED_FALLBACK_ENABLE",
                "ARL_RUST_ACCEL_API_UNIFIED_MODE",
                "ARL_RUST_ACCEL_API_UNIFIED_RUST_STAGES",
            ):
                self.assertIn(key, env_keys, f"{service} 缺少应用配置透传 {key}")

    def test_compose_required_variables_covered_by_examples(self):
        content = read(COMPOSE_FILE)
        required_vars = set(re.findall(r"\$\{([A-Z0-9_]+):\?", content))
        self.assertTrue(required_vars, "docker-compose.yml 应存在 :? 必填变量")
        for path in (ENV_EXAMPLE_ROOT, ENV_EXAMPLE_DOCKER):
            parsed = parse_env_example(path)
            uncovered = required_vars - set(parsed)
            self.assertEqual(uncovered, set(), f"{path.name} 未覆盖 compose 必填变量: {uncovered}")

    def test_no_legacy_weak_secrets_in_governance_surface(self):
        for path in (
            DOCKER_DIR / "config-docker.yaml",
            ARL_ROOT / "app" / "config.yaml.example",
            ARL_ROOT / "app" / "config.py",
            CHECK_SCRIPT,
        ):
            content = read(path)
            for weak in LEGACY_WEAK_SECRETS:
                if path == CHECK_SCRIPT:
                    # 预检脚本的黑名单必须包含历史泄露值（仅此处允许字面量存在）。
                    self.assertIn(weak, content)
                else:
                    self.assertNotIn(weak, content, f"{path.name} 仍残留弱凭据字面量: {weak}")


class TestStartupArgContamination(unittest.TestCase):
    """诊断只走 stderr：启动参数来源路径的 stdout 必须干净。"""

    def _run_python(self, code, env_extra=None):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(ARL_ROOT),
        }
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["python3", "-c", code],
            cwd=str(ARL_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    @unittest.skipUnless(
        (ARL_ROOT / "app" / "config.yaml").is_file(),
        "本地无 ARL/app/config.yaml（未跟踪），跳过 import 级断言",
    )
    def test_import_config_writes_nothing_to_stdout(self):
        proc = self._run_python("import app.config")
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertEqual(proc.stdout, "", "app.config import 期不得向 stdout 输出诊断")

    def test_get_cfg_int_guard_present_in_both_startup_scripts(self):
        # web/worker 两个启动脚本必须同源携带“末行+整数校验”防御，防止未来分叉。
        guard_re = re.compile(r"value=\"\$\(printf.*?esac", re.S)
        blocks = []
        for name in ("start_web.sh", "start_worker.sh"):
            content = read(DOCKER_DIR / "worker" / name)
            match = guard_re.search(content)
            self.assertIsNotNone(match, f"{name} 缺少 get_cfg_int 噪声防御块")
            blocks.append(re.sub(r"\s+", " ", match.group(0)))
        self.assertEqual(blocks[0], blocks[1], "web/worker 的 get_cfg_int 防御块已分叉")

    def test_get_cfg_int_guard_behavior(self):
        # 提取真实脚本中的防御块执行（不复制实现）：噪声取末行、非数字回默认。
        guard_re = re.compile(r"(value=\"\$\(printf.*?esac)", re.S)
        content = read(DOCKER_DIR / "worker" / "start_web.sh")
        match = guard_re.search(content)
        self.assertIsNotNone(match)
        script = (
            "run_guard() {\n"
            "  local value=\"$1\"\n"
            "  local default_value=42\n"
            f"  {match.group(1)}\n"
            "  printf '%s' \"$value\"\n"
            "}\n"
            "run_guard \"$1\"\n"
        )
        cases = {
            "5": "5",
            "noise line\n8": "8",
            "not-a-number": "42",
            "": "42",
            "1\n2": "2",
        }
        if not shutil.which("bash"):
            self.skipTest("bash 不可用")
        for raw_input, expected in cases.items():
            proc = subprocess.run(
                ["bash", "-c", script, "_", raw_input],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, expected, f"输入 {raw_input!r} 的净化结果不符")


class TestCredentialInjectionChain(unittest.TestCase):
    """inject_url_credentials 纯函数 + 子进程端到端注入（无本进程槽位污染）。"""

    def test_pure_function(self):
        from app.config import inject_url_credentials

        self.assertEqual(
            inject_url_credentials("mongodb://mongodb:27017/", "u1", "p1"),
            "mongodb://u1:p1@mongodb:27017/",
        )
        self.assertEqual(
            inject_url_credentials("mongodb://old:cred@mongodb:27017/", "u1", "p1"),
            "mongodb://u1:p1@mongodb:27017/",
        )
        self.assertEqual(
            inject_url_credentials("amqp://rabbitmq:5672/arlv2host", "u1", "p@ss:w/rd"),
            "amqp://u1:p%40ss%3Aw%2Frd@rabbitmq:5672/arlv2host",
        )
        self.assertIsNone(inject_url_credentials("http://x/", "u", "p"))
        self.assertIsNone(inject_url_credentials("", "u", "p"))

    @unittest.skipUnless(
        (ARL_ROOT / "app" / "config.yaml").is_file(),
        "本地无 ARL/app/config.yaml（未跟踪），跳过子进程端到端断言",
    )
    def test_component_env_injects_credentials(self):
        env = {
            "MONGO_INITDB_ROOT_USERNAME": "svc_root",
            "MONGO_INITDB_ROOT_PASSWORD": FIXTURE_MONGO_PASS,
            "RABBITMQ_DEFAULT_USER": "arl_svc",
            "RABBITMQ_DEFAULT_PASS": FIXTURE_AMQP_PASS,
            "ARL_API_UNIFIED_ENABLE": "true",
            "ARL_API_UNIFIED_FALLBACK_ENABLE": "false",
        }
        code = (
            "from urllib.parse import quote_plus\n"
            "from app.config import Config\n"
            "ok = True\n"
            "ok &= quote_plus(%r) in Config.MONGO_URL\n"
            "ok &= Config.MONGO_URL.split('://', 1)[1].startswith('svc_root:%%s@' %% quote_plus(%r))\n"
            "ok &= quote_plus(%r) in Config.CELERY_BROKER_URL\n"
            "ok &= Config.API_UNIFIED_ENABLE is True\n"
            "ok &= Config.API_UNIFIED_FALLBACK_ENABLE is False\n"
            "raise SystemExit(0 if ok else 1)\n"
        ) % (FIXTURE_MONGO_PASS, FIXTURE_MONGO_PASS, FIXTURE_AMQP_PASS)
        proc = TestStartupArgContamination._run_python(self, code, env)
        # 断言消息不回显完整连接串，仅保留退出码定位。
        self.assertEqual(proc.returncode, 0, f"注入未生效 rc={proc.returncode}")

    @unittest.skipUnless(
        (ARL_ROOT / "app" / "config.yaml").is_file(),
        "本地无 ARL/app/config.yaml（未跟踪），跳过子进程端到端断言",
    )
    def test_explicit_url_env_is_authoritative(self):
        env = {
            "ARL_MONGO_URL": "mongodb://explicit-host:27017/",
            "MONGO_INITDB_ROOT_USERNAME": "svc_root",
            "MONGO_INITDB_ROOT_PASSWORD": FIXTURE_MONGO_PASS,
        }
        code = (
            "from app.config import Config\n"
            "raise SystemExit(0 if Config.MONGO_URL == 'mongodb://explicit-host:27017/' else 1)\n"
        )
        proc = TestStartupArgContamination._run_python(self, code, env)
        self.assertEqual(proc.returncode, 0, "显式 ARL_MONGO_URL 应完全接管")

    @unittest.skipUnless(
        (ARL_ROOT / "app" / "config.yaml").is_file(),
        "本地无 ARL/app/config.yaml（未跟踪），跳过子进程端到端断言",
    )
    def test_no_env_keeps_config_yaml_value(self):
        code = (
            "from app.config import Config\n"
            "raise SystemExit(0 if %r not in Config.MONGO_URL and %r not in Config.CELERY_BROKER_URL else 1)\n"
        ) % (FIXTURE_MONGO_PASS, FIXTURE_AMQP_PASS)
        proc = TestStartupArgContamination._run_python(self, code)
        self.assertEqual(proc.returncode, 0, "凭据 env 缺失时不得注入 fixture 值")


class TestDeployEnvPreflight(unittest.TestCase):
    """check-deploy-env.sh 必填/占位/弱值告警/缺失四类路径。"""

    GOOD_ENV = (
        "MONGO_INITDB_ROOT_USERNAME=svc_root\n"
        "MONGO_INITDB_ROOT_PASSWORD=Xk9#mQ2vLp7rTz4w\n"
        "ARL_APP_USERNAME=arl_admin\n"
        "ARL_APP_PASSWORD=Vm8xQ3pL7kNz2wYd\n"
        "RABBITMQ_DEFAULT_USER=arl_svc\n"
        "RABBITMQ_DEFAULT_PASS=Hg6tRq9zXb4mKp2v\n"
        "BASIC_AUTH_PASSWORD=Zq7wNm3vBt8kXd6y\n"
        "BASIC_AUTH_USERNAME=ops\n"
        "NGINX_LISTEN_PORT=80\n"
    )

    def _run(self, env_text=None, env_file=None):
        if not shutil.which("bash"):
            self.skipTest("bash 不可用")
        if env_file is None:
            tmp = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False)
            tmp.write(env_text)
            tmp.close()
            env_file = tmp.name
        try:
            proc = subprocess.run(
                ["bash", str(CHECK_SCRIPT), env_file],
                capture_output=True,
                text=True,
                timeout=30,
            )
        finally:
            if env_text is not None:
                os.unlink(env_file)
        # 敏感值绝不允许出现在任何输出通道。
        if env_text:
            for line in env_text.splitlines():
                value = line.split("=", 1)[1] if "=" in line else ""
                if value and value not in ("<set-me>", "admin"):
                    self.assertNotIn(value, proc.stdout + proc.stderr)
        return proc

    def test_good_env_passes(self):
        proc = self._run(self.GOOD_ENV)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_missing_key_rejected(self):
        env = "\n".join(
            line for line in self.GOOD_ENV.splitlines() if not line.startswith("RABBITMQ_DEFAULT_PASS")
        )
        proc = self._run(env + "\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("RABBITMQ_DEFAULT_PASS", proc.stderr)

    def test_placeholder_rejected(self):
        env = self.GOOD_ENV.replace(
            "ARL_APP_PASSWORD=Vm8xQ3pL7kNz2wYd", "ARL_APP_PASSWORD=<set-me>"
        )
        proc = self._run(env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("占位", proc.stderr)

    def test_weak_value_warns_but_does_not_block(self):
        env = self.GOOD_ENV.replace(
            "MONGO_INITDB_ROOT_PASSWORD=Xk9#mQ2vLp7rTz4w", "MONGO_INITDB_ROOT_PASSWORD=admin"
        )
        proc = self._run(env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARNING", proc.stderr)
        self.assertIn("MONGO_INITDB_ROOT_PASSWORD", proc.stderr)

    def test_missing_file_rejected(self):
        proc = self._run(env_file=str(DOCKER_DIR / "__no_such_env__.local"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn(".env", proc.stderr)


class TestInitDeployEnv(unittest.TestCase):
    """init-deploy-env.sh：内部凭据自动生成、幂等持久化、用户项边界。"""

    INIT_SCRIPT = DOCKER_DIR / "init-deploy-env.sh"

    def _run_init(self, env_file, stdin_devnull=True):
        if not shutil.which("bash"):
            self.skipTest("bash 不可用")
        return subprocess.run(
            ["bash", str(self.INIT_SCRIPT), env_file],
            stdin=subprocess.DEVNULL if stdin_devnull else None,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _env_map(self, env_file):
        parsed = {}
        for line in read(pathlib.Path(env_file)).splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, value = stripped.split("=", 1)
                parsed[key.strip()] = value.strip()
        return parsed

    INTERNAL_KEYS = (
        "MONGO_INITDB_ROOT_USERNAME",
        "MONGO_INITDB_ROOT_PASSWORD",
        "RABBITMQ_DEFAULT_USER",
        "RABBITMQ_DEFAULT_PASS",
    )

    def test_fresh_init_generates_internal_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sub", ".env")
            proc = self._run_init(target)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(os.path.isfile(target), "非交互模式也应创建 .env")
            parsed = self._env_map(target)
            for key in self.INTERNAL_KEYS:
                self.assertNotIn(parsed.get(key, ""), ("", "<set-me>"), f"{key} 应自动生成")
            # 随机值特征：密码 32 位十六进制、用户名可读前缀、四个键互不相同。
            self.assertRegex(parsed["MONGO_INITDB_ROOT_PASSWORD"], r"^[0-9a-f]{32}$")
            self.assertRegex(parsed["RABBITMQ_DEFAULT_PASS"], r"^[0-9a-f]{32}$")
            self.assertTrue(parsed["MONGO_INITDB_ROOT_USERNAME"].startswith("root_"))
            self.assertTrue(parsed["RABBITMQ_DEFAULT_USER"].startswith("arl_"))
            self.assertEqual(len({parsed[k] for k in self.INTERNAL_KEYS}), 4)
            # 用户填写项不被自动生成（任务边界）：Basic Auth / ARL 密码保持占位。
            self.assertEqual(parsed["BASIC_AUTH_PASSWORD"], "<set-me>")
            self.assertEqual(parsed["ARL_APP_PASSWORD"], "<set-me>")
            self.assertEqual(parsed["ARL_APP_USERNAME"], "admin")
            mode = os.stat(target).st_mode & 0o777
            self.assertEqual(oct(mode), oct(0o600), "凭据文件必须 600")
            # 值不回显。
            for key in self.INTERNAL_KEYS:
                self.assertNotIn(parsed[key], proc.stdout + proc.stderr)

    def test_init_is_idempotent_and_preserves_existing_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, ".env")
            self._run_init(target)
            first = self._env_map(target)
            # 用户手工值不被二次运行覆盖。
            with open(target, "a", encoding="utf-8") as fh:
                fh.write("BASIC_AUTH_PASSWORD=user-persisted-1\n")
            proc = self._run_init(target)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            second = self._env_map(target)
            for key in self.INTERNAL_KEYS:
                self.assertEqual(first[key], second[key], f"{key} 在重复执行中被重生成")
            self.assertEqual(second["BASIC_AUTH_PASSWORD"], "user-persisted-1")
            self.assertIn("保持不变", proc.stdout)

    def test_init_backfills_missing_internal_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, ".env")
            self._run_init(target)
            kept = [
                line for line in read(pathlib.Path(target)).splitlines()
                if not line.startswith("RABBITMQ_DEFAULT_PASS=")
            ]
            pathlib.Path(target).write_text("\n".join(kept) + "\n", encoding="utf-8")
            proc = self._run_init(target)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            parsed = self._env_map(target)
            self.assertRegex(parsed.get("RABBITMQ_DEFAULT_PASS", ""), r"^[0-9a-f]{32}$")

    def test_init_result_then_precheck_flags_user_keys_only(self):
        # 联动：init 产物在用户补齐 Basic/ARL 密码前，预检必须只点名这两个键。
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, ".env")
            self._run_init(target)
            proc = subprocess.run(
                ["bash", str(CHECK_SCRIPT), target],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("BASIC_AUTH_PASSWORD", proc.stderr)
            self.assertIn("ARL_APP_PASSWORD", proc.stderr)
            self.assertNotIn("MONGO_INITDB_ROOT", proc.stderr)
            self.assertNotIn("RABBITMQ_DEFAULT", proc.stderr)


@unittest.skipUnless(shutil.which("docker"), "docker CLI 不可用，跳过 compose 渲染级检查")
class TestComposeRequiresCredentials(unittest.TestCase):
    """docker compose config 级别的启动前失败证据（无需 daemon）。"""

    def _compose(self, env_text):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False)
        tmp.write(env_text)
        tmp.close()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        try:
            proc = subprocess.run(
                [
                    "docker", "compose",
                    "-f", str(COMPOSE_FILE),
                    "--env-file", tmp.name,
                    "config", "--quiet",
                ],
                cwd=str(DOCKER_DIR),
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
        finally:
            os.unlink(tmp.name)
        return proc

    def test_missing_credentials_rejected(self):
        proc = self._compose("NGINX_LISTEN_PORT=80\n")
        self.assertNotEqual(proc.returncode, 0, "缺凭据时 compose 必须拒绝渲染")
        merged = proc.stdout + proc.stderr
        # compose 遇首个无法插值的 :? 变量即失败；断言“点名缺失变量+其必填消息”。
        self.assertTrue(
            re.search(r"(?s)required variable (\w+) is missing a value.*"
                      r"(must be set|set .* in \.env|\.env\.example)", merged),
            f"错误信息未点名缺失变量: {merged[-300:]}",
        )

    def test_full_credentials_render_ok(self):
        proc = self._compose(TestDeployEnvPreflight.GOOD_ENV)
        self.assertEqual(proc.returncode, 0, (proc.stdout + proc.stderr)[-400:])


if __name__ == "__main__":
    unittest.main()
