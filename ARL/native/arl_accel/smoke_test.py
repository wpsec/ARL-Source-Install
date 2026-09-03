#!/usr/bin/env python3
"""验证生产镜像中 Rust 扩展的导入和最小批处理能力。"""
import arl_accel


def main():
    records = arl_accel.extract_urlfinder_candidates(
        [
            (
                "https://example.test/app/index.html",
                '<script src="/static/app.js"></script><a href="/api/users">users</a>',
                "https://example.test/app/index.html",
                0,
                False,
            )
        ],
        ["example.test"],
        True,
        20,
        20,
        2,
    )
    contents = {item[1] for item in records}
    if "https://example.test/static/app.js" not in contents:
        raise AssertionError("Rust extraction smoke test missed JS candidate")
    if "https://example.test/api/users" not in contents:
        raise AssertionError("Rust extraction smoke test missed URL candidate")
    if any("other.test" in item for item in contents):
        raise AssertionError("Rust extraction smoke test accepted cross-domain candidate")

    targets = arl_accel.rank_sensitive_targets(
        [
            (
                "urlfinder_url",
                "https://example.test/admin/export?id=1",
                "https://example.test/app.js",
                "https://example.test",
            )
        ],
        ["https://example.test"],
        [],
        True,
        10,
    )
    if not targets or targets[0][0] != "https://example.test/admin/export?id=1":
        raise AssertionError("Rust ranking smoke test returned an unexpected target")

    html_records = arl_accel.extract_html_candidates(
        [
            (
                "https://example.test/index.html",
                '<a href="/admin">admin</a><form action="/login" method="post">'
                '<input name="username"></form><script src="/static/app.js"></script>',
                "https://example.test/index.html",
                0,
                False,
            )
        ],
        ["example.test"],
        ["example.test"],
        ["example.test"],
    )
    if not any(item[0] == "page_link" for item in html_records):
        raise AssertionError("Rust HTML smoke test missed page link")
    if not any(item[0] == "page_form" for item in html_records):
        raise AssertionError("Rust HTML smoke test missed page form")

    js_records = arl_accel.extract_js_endpoint_candidates(
        [
            (
                "https://example.test/static/app.js",
                'fetch("/api/v1/users"); const docs = "/v3/api-docs";',
                "https://example.test/static/app.js",
                0,
                True,
            )
        ],
        ["example.test"],
        100,
    )
    if not any(item[1] == "https://example.test/api/v1/users" for item in js_records):
        raise AssertionError("Rust JS smoke test missed endpoint")
    print("arl-accel-smoke-ok")


if __name__ == "__main__":
    main()
