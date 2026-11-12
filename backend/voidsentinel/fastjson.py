"""orjson when installed (several times faster), stdlib json otherwise."""
try:
    import orjson as _o

    def loads(s):
        return _o.loads(s)

    def dumps(obj) -> str:
        return _o.dumps(obj).decode()
except ImportError:  # pragma: no cover
    import json as _j

    def loads(s):
        return _j.loads(s)

    def dumps(obj) -> str:
        return _j.dumps(obj, separators=(",", ":"))
