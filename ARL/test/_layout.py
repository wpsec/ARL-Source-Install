import pathlib


TEST_ROOT = pathlib.Path(__file__).resolve().parent
ARL_ROOT = TEST_ROOT.parent
PROJECT_ROOT = ARL_ROOT.parent

# 源码仓库与发布镜像的唯一区别是是否把 ARL 目录扁平化到 /code。
if not (PROJECT_ROOT / "scripts").is_dir() and (ARL_ROOT / "scripts").is_dir():
    PROJECT_ROOT = ARL_ROOT
