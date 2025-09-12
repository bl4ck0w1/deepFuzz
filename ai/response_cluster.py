import re
import json
import math
import random
import hashlib
import urllib.parse as urlparse
from collections import defaultdict, deque
from concurrent import futures
import grpc
import response_cluster_pb2 as pb
import response_cluster_pb2_grpc as rpc

random.seed(1337)

_TAG_RE = re.compile(rb"<[^>]+>")
_WS_RE = re.compile(rb"\s+")

_SOFT404_MARKERS = tuple([
    b"not found", b"page not found", b"error 404", b"does not exist",
    b"the requested url was not found", b"forbidden", b"access denied",
    b"unauthorized", b"login required", b"maintenance", b"coming soon",
    b"temporarily unavailable", b"invalid url", b"resource cannot be found",
])

def _hostname(url: str) -> str:
    try:
        return urlparse.urlsplit(url).hostname or ""
    except Exception:
        return ""

def _normalize(content: bytes) -> bytes:
    c = content or b""
    c = _TAG_RE.sub(b" ", c)
    c = c.lower()
    c = _WS_RE.sub(b" ", c).strip()
    return c

def _word_shingles(text: bytes, k: int = 5) -> set:
    words = text.split()
    if len(words) < k:
        return set([b" ".join(words)]) if words else set()
    return set(b" ".join(words[i:i+k]) for i in range(len(words) - k + 1))

def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    uni = len(a | b)
    return inter / max(1, uni)

class SimilarityService(rpc.SimilarityServicer):
    def __init__(self):
        self._sig_count = defaultdict(int)
        self._sig_paths = defaultdict(lambda: deque(maxlen=64))
        self._soft404_proto = defaultdict(list) 
        self._max_protos_per_host = 8
        self._cluster_map = {}
        self._cluster_cap = 100_000

    def Validate(self, request, context):
        url = request.url or ""
        sha = (request.response_sha or "").lower()
        code = int(request.status_code)
        host = _hostname(url)
        path = urlparse.urlsplit(url).path or "/"
        key = (host, sha)

        self._sig_count[key] += 1
        paths = self._sig_paths[key]
        if not paths or paths[-1] != path:
            paths.append(path)

        if code in (204, 301, 302, 303, 307, 308):
            return pb.ValidationResponse(is_valid=False)

        path_diversity = len(set(paths))
        if code == 200 and self._sig_count[key] >= 5 and path_diversity >= 5:
            return pb.ValidationResponse(is_valid=False)

        return pb.ValidationResponse(is_valid=True)

    def IsSoft404(self, request, context):
        content = bytes(request.content or b"")
        url = request.url or ""
        host = _hostname(url)
        norm = _normalize(content)
        if len(norm) < 80:
            return pb.Soft404Response(is_soft404=True)

        marker_hits = sum(1 for m in _SOFT404_MARKERS if m in norm)
        marker_score = marker_hits / 4.0 

        sh = _word_shingles(norm, k=5)
        sim_max = 0.0
        for proto in self._soft404_proto.get(host, []):
            sim_max = max(sim_max, _jaccard(sh, proto))

        is_soft = (sim_max >= 0.86) or (marker_score >= 1.0)

        if marker_hits >= 2:
            protos = self._soft404_proto[host]
            if len(protos) < self._max_protos_per_host:
                protos.append(sh)
            else:
                i = random.randrange(self._max_protos_per_host)
                protos[i] = sh

        return pb.Soft404Response(is_soft404=is_soft)

    def ClusterResponse(self, request, context):
        sha = (request.response_sha or "").lower()
        cid = request.cluster_id or ""

        if sha in self._cluster_map:
            cid = self._cluster_map[sha]
        else:
            cid = cid or f"cls-{sha[:10] or 'nil'}"
            if len(self._cluster_map) >= self._cluster_cap:
                k = random.choice(list(self._cluster_map.keys()))
                self._cluster_map.pop(k, None)
            self._cluster_map[sha] = cid

        return pb.ClusterResponse(cluster_id=cid)


def serve(addr: str = "[::]:50053]", workers: int = 16):
    options = [
        ("grpc.max_send_message_length", 32 * 1024 * 1024),
        ("grpc.max_receive_message_length", 32 * 1024 * 1024),
        ("grpc.keepalive_time_ms", 20000),
        ("grpc.keepalive_timeout_ms", 5000),
    ]
    srv = grpc.server(
        futures.ThreadPoolExecutor(max_workers=workers),
        options=options,
        compression=grpc.Compression.Gzip,
    )
    rpc.add_SimilarityServicer_to_server(SimilarityService(), srv)
    srv.add_insecure_port(addr.replace("]", "")) 
    srv.start()
    srv.wait_for_termination()

if __name__ == "__main__":
    serve()
