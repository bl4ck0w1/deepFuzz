import os
import json
import math
import random
import base64
import string
import urllib.parse as urlparse
from concurrent import futures
import grpc

try:
    import tensorflow as tf
    _HAVE_TF = True
except Exception:
    _HAVE_TF = False

import waf_generator_pb2 as pb
import waf_generator_pb2_grpc as rpc
random.seed(1337)

if _HAVE_TF:
    class WAFGAN(tf.keras.Model):
        def __init__(self, in_dim=512, out_dim=512, ckpt='/models/waf_gan_generator_v3.h5'):
            super().__init__()
            self.in_dim = in_dim
            self.out_dim = out_dim
            self.generator = tf.keras.Sequential([
                tf.keras.layers.Input(shape=(in_dim,)),
                tf.keras.layers.Dense(256, activation='relu'),
                tf.keras.layers.Dense(512, activation='relu'),
                tf.keras.layers.Dense(out_dim, activation=None),
            ])
            try:
                if os.path.exists(ckpt):
                    self.generator.load_weights(ckpt)
            except Exception:
                pass
        def call(self, z, training=False):
            return self.generator(z, training=training)

class WAFGenerator(rpc.WAFGeneratorServicer):
    def __init__(self):
        self.gan = WAFGAN() if _HAVE_TF else None
        self.feedback = [] 

    def GenerateEvasion(self, request, context):
        target_url = (request.target_url or "").strip()
        raw = bytes(getattr(request, "original_payload", b"") or b"")
        evaded = self._evade_url(target_url)
        adv = self._mutate_bytes(raw) if raw else b""
        return pb.EvadeResponse(evaded_url=evaded, adversarial_payload=adv)

    def MutatePath(self, request, context):
        path = request.original_path or "/"
        variants = self._create_variants(path, limit=64)
        return pb.MutateResponse(variants=variants)

    def AdversarialFeedback(self, request, context):
        self.feedback.append({
            "payload_len": len(request.payload or b""),
            "was_blocked": bool(request.was_blocked),
            "waf": getattr(request, "waf_type", ""),
        })
        self.feedback = self.feedback[-2048:]
        return pb.FeedbackResponse(ack=True)

    def _evade_url(self, url: str) -> str:
        if not url:
            return ""
        try:
            u = urlparse.urlsplit(url)
        except Exception:
            return url

        base_qs = urlparse.parse_qsl(u.query, keep_blank_values=True)
        variants = self._create_variants(u.path or "/", limit=24)
        cands = []
        for p in variants:
            qs = self._mutate_query(base_qs)
            qstr = urlparse.urlencode(qs, doseq=True)
            cands.append(urlparse.urlunsplit((u.scheme, u.netloc, p, qstr, u.fragment)))

        def score(v: str) -> float:
            s = 0.0
            if "%25" in v or "%2e" in v.lower(): s += 0.6
            if "%2f" in v.lower(): s += 0.4
            if "%00" in v.lower(): s += 0.2
            if ";;" in v or "/./" in v or "/../" in v: s += 0.4
            if "%u" in v.lower(): s += 0.3
            s += (len(v) % 7) * 0.01
            return s

        best = max(cands, key=score) if cands else url
        return best

    def _mutate_query(self, pairs):
        pairs = list(pairs)
        random.shuffle(pairs)
        pairs.append((self._rand_key(3), self._rand_key(6)))
        if pairs and random.random() < 0.35:
            k, v = random.choice(pairs)
            pairs.append((k, v + ";" + self._rand_key(4)))
        return pairs

    def _mutate_bytes(self, b: bytes) -> bytes:
        if not b:
            return b""
        if self.gan is not None:
            try:
                raw = b[:512]
                pad = max(0, 512 - len(raw))
                z = tf.convert_to_tensor([list(raw) + [0]*pad], dtype=tf.float32)
                adv = self.gan(z, training=False).numpy().astype("int32")[0]
                adv = bytes([max(0, min(255, v)) for v in adv])
                return base64.urlsafe_b64encode(adv).rstrip(b"=")
            except Exception:
                pass
        enc = base64.urlsafe_b64encode(b).rstrip(b"=")
        if len(enc) > 8:
            i = random.randint(1, min(8, len(enc)-1))
            enc = enc[i:] + enc[:i]
        return enc

    def _create_variants(self, path: str, limit: int = 64):
        path = path or "/"
        if not path.startswith("/"):
            path = "/" + path

        segs = [s for s in path.split("/") if s]
        if not segs:
            segs = [""]

        V = set()
        add = V.add
        add(path)

        add(self._double_encode(path))
        add(self._rtlo_inject(path))
        add(self._slash_obfuscate(path))
        add(self._case_toggle(path))
        add(self._unicode_pad(path))
        add(self._dots_insert(path))
        add(self._semicolon_matrix(path))

        for i in range(len(segs)):
            add(self._percent_encode_segment(path, i))
            add(self._split_with_delims(path, i, ";"))
            add(self._split_with_delims(path, i, "%2f"))
            add(self._insert_noise_segment(path, i))

        for _ in range(16):
            add(self._jitter(path))

        out = [v for v in V if v and v.startswith("/")]
        random.shuffle(out)
        return out[:limit]

    def _double_encode(self, s: str) -> str:
        return urlparse.quote(urlparse.quote(s, safe=""), safe="")

    def _rtlo_inject(self, s: str) -> str:
        return s.replace("/", "/\u202e") if random.random() < 0.5 else s

    def _slash_obfuscate(self, s: str) -> str:
        return s.replace("/", "/%2F")

    def _case_toggle(self, s: str) -> str:
        def flip(c): return c.upper() if c.islower() else c.lower()
        return "".join(flip(c) if c.isalpha() and random.random() < 0.5 else c for c in s)

    def _unicode_pad(self, s: str) -> str:
        pads = ["\u200b", "\u2060", "\ufeff"]
        return "/".join(seg + random.choice(pads) if seg else seg for seg in s.split("/"))

    def _dots_insert(self, s: str) -> str:
        return s.replace("/", "/./")

    def _semicolon_matrix(self, s: str) -> str:
        return s.replace("/", "/;")

    def _percent_encode_segment(self, s: str, idx: int) -> str:
        segs = s.split("/")
        if 0 <= idx < len(segs) and segs[idx]:
            segs[idx] = urlparse.quote(segs[idx], safe="")
        return "/".join(segs)

    def _split_with_delims(self, s: str, idx: int, token: str) -> str:
        segs = s.split("/")
        if 0 <= idx < len(segs) and segs[idx]:
            segs[idx] = token.join([c for c in segs[idx]])
        return "/".join(segs)

    def _insert_noise_segment(self, s: str, idx: int) -> str:
        segs = s.split("/")
        noise = self._rand_key(2)
        if 0 <= idx < len(segs):
            segs.insert(idx, noise)
        return "/".join(segs)

    def _jitter(self, s: str) -> str:
        if len(s) < 2: return s
        i = random.randint(1, len(s) - 1)
        if random.random() < 0.5:
            return s[:i] + s[i] + s[i:]
        return s[:i] + urlparse.quote(s[i]) + s[i+1:]

    def _rand_key(self, n: int) -> str:
        alph = string.ascii_letters + string.digits
        return "".join(random.choice(alph) for _ in range(n))


def serve(addr: str = "[::]:50052]", workers: int = 16):
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
    rpc.add_WAFGeneratorServicer_to_server(WAFGenerator(), srv)
    srv.add_insecure_port(addr.replace("]", "")) 
    srv.start()
    srv.wait_for_termination()


if __name__ == "__main__":
    serve()
