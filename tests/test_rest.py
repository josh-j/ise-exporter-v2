"""ISERestClient.get_ers must follow nextPage.href across all pages iteratively
(no per-page recursion that would blow the stack on large result sets)."""
from ise_exporter.clients.rest import ISERestClient


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def test_get_ers_paginates_iteratively():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    base = "https://h:9060/ers/config/networkdevice"
    pages = {
        base: {"SearchResult": {"resources": [{"id": "1"}],
                                "nextPage": {"href": base + "?page=2"}}},
        base + "?page=2": {"SearchResult": {"resources": [{"id": "2"}],
                                            "nextPage": {"href": base + "?page=3"}}},
        base + "?page=3": {"SearchResult": {"resources": [{"id": "3"}]}},
    }
    seen = []

    def fake_request(session, url, params=None, timeout=30, api_name="x"):
        seen.append(url)
        return _Resp(pages[url])

    c._request = fake_request
    res = c.get_ers("/config/networkdevice", {"size": 1}, get_all=True)
    assert [r["id"] for r in res] == ["1", "2", "3"]
    assert len(seen) == 3  # one request per page, no recursion


def test_get_ers_single_page_when_not_get_all():
    c = ISERestClient.__new__(ISERestClient)
    c.ers_url = "https://h:9060/ers"
    c.session = None
    c._request = lambda *a, **k: _Resp(
        {"SearchResult": {"resources": [{"id": "1"}], "nextPage": {"href": "x/ers/more"}}})
    res = c.get_ers("/config/networkdevice")
    assert [r["id"] for r in res] == ["1"]
