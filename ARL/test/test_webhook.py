"""Webhook dispatch tests use patched constructors to avoid DB and HTTP access."""

import unittest
from unittest.mock import patch

import app.services.webhook as webhook
from app.services.webhook import (
    domain_asset_web_hook,
    ip_asset_web_hook,
    site_asset_web_hook,
)


class TestAssetWebhookDispatch(unittest.TestCase):
    def _assert_dispatch(self, function, class_name):
        with patch.object(webhook.Config, "WEB_HOOK_URL", "fixture-webhook-url"), \
                patch.object(webhook.Config, "WEB_HOOK_TOKEN", ""), \
                patch.object(webhook, class_name) as hook:
            function(task_id="fixture-task", scope_id="fixture-scope")

        hook.assert_called_once_with(
            task_id="fixture-task",
            scope_id="fixture-scope",
            web_hook_url="fixture-webhook-url",
            web_hook_token="",
        )

    def test_ip_asset_web_hook_dispatches(self):
        self._assert_dispatch(ip_asset_web_hook, "IPAssetWebHook")

    def test_domain_asset_web_hook_dispatches(self):
        self._assert_dispatch(domain_asset_web_hook, "DomainAssetWebHook")

    def test_site_asset_web_hook_dispatches(self):
        self._assert_dispatch(site_asset_web_hook, "SiteAssetWebHook")


if __name__ == "__main__":
    unittest.main()
