"""Runtime shim (loaded via PYTHONPATH) so urllib sends a User-Agent that
Cloudflare does not block with error 1010. Does not touch e2e-verify.py."""
import urllib.request

_orig_init = urllib.request.Request.__init__


def _patched_init(self, fullurl, data=None, headers={}, origin_req_host=None,
                  unverifiable=False, method=None):
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "AuditForgeE2E/1.0")
    _orig_init(self, fullurl, data=data, headers=headers,
               origin_req_host=origin_req_host, unverifiable=unverifiable,
               method=method)


urllib.request.Request.__init__ = _patched_init
