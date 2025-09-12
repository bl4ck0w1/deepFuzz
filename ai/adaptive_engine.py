import os
import math
import time
import numpy as np
from concurrent import futures

try:
    import torch
    from torch import nn
    _HAVE_TORCH = True
except Exception:
    _HAVE_TORCH = False

try:
    import torch_geometric
    from torch_geometric.data import Data as GeometricData
    from torch_geometric.nn import GCNConv
    _HAVE_PYG = True
except Exception:
    _HAVE_PYG = False

import grpc
import adaptive_engine_pb2 as pb
import adaptive_engine_pb2_grpc as rpc

if _HAVE_TORCH:
    class MLPScorer(nn.Module):
        def __init__(self, in_dim: int):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(in_dim, 64), nn.ReLU(),
                nn.Linear(64, 32), nn.ReLU(),
                nn.Linear(32, 1), nn.Sigmoid(),
            )
        def forward(self, x):
            return self.net(x).view(-1)

    class GNNScorer(nn.Module):
        def __init__(self, in_dim: int):
            super().__init__()
            hid = 64
            self.g1 = GCNConv(in_dim, hid)
            self.g2 = GCNConv(hid, 32)
            self.mlp = nn.Sequential(
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, 1), nn.Sigmoid(),
            )
        def forward(self, data: 'GeometricData'):
            x = data.x
            x = torch.relu(self.g1(x, data.edge_index))
            x = torch.relu(self.g2(x, data.edge_index))
            return self.mlp(x).view(-1)

class AdaptiveEngine(rpc.AdaptiveEngineServicer):
    def __init__(self):
        self.feedback_buffer = []
        self.model = None
        self.model_type = "heuristic"  
        self.in_dim = 16  

        if _HAVE_TORCH:
            ckpt = "/models/gnn_path_predictor_v4.pt"
            try:
                if _HAVE_PYG and os.path.exists(ckpt):
                    self.model = GNNScorer(self.in_dim)
                    self.model.load_state_dict(torch.load(ckpt, map_location="cpu"))
                    self.model.eval()
                    self.model_type = "gnn"
                else:
                    self.model = MLPScorer(self.in_dim)
                    mlp_ckpt = "/models/mlp_path_scorer.pt"
                    if os.path.exists(mlp_ckpt):
                        self.model.load_state_dict(torch.load(mlp_ckpt, map_location="cpu"))
                    self.model.eval()
                    self.model_type = "mlp"
            except Exception:
                self.model = None
                self.model_type = "heuristic"

    def Prioritize(self, request, context):
        reqs = list(request.requests)
        if not reqs:
            return pb.PrioritizeResponse(next_target="")

        feats = self._featurize_requests(reqs)
        scores = None
        try:
            if self.model_type in ("gnn", "mlp") and _HAVE_TORCH and self.model is not None:
                with torch.no_grad():
                    if self.model_type == "gnn" and _HAVE_PYG:
                        data = self._build_graph(feats)
                        tscores = self.model(data).cpu().numpy()
                    else:
                        tx = torch.from_numpy(feats).float()
                        tscores = self.model(tx).cpu().numpy()
                scores = tscores
        except Exception:
            scores = None

        if scores is None:
            scores = np.array([self._heuristic_score(r) for r in reqs], dtype=np.float32)

        idx = int(np.argmax(scores))
        return pb.PrioritizeResponse(next_target=reqs[idx].url)

    def Evaluate(self, request, context):
        s = int(request.status_code)
        sha = (request.response_sha or "")[:16]
        base = 0.1
        if s == 200:
            base = 0.90
        elif s in (401, 403):
            base = 0.55
        elif 500 <= s < 600:
            base = 0.65
        else:
            base = 0.25
        jitter = (sum(ord(c) for c in sha) % 7) / 100.0
        score = min(0.99, max(0.01, base + jitter))
        return pb.EvaluateResponse(score=score)

    def Feedback(self, request, context):
        self.feedback_buffer.append({
            "t": time.time(),
            "path": getattr(request, "path", ""),
            "is_critical": bool(getattr(request, "is_critical", False)),
            "is_false_positive": bool(getattr(request, "is_false_positive", False)),
        })
        if len(self.feedback_buffer) >= 2000 and _HAVE_TORCH and self.model is not None:
            try:
                self._reinforce_model(self.feedback_buffer[-2000:])
            except Exception:
                pass
        return pb.FeedbackResponse(ack=True)

    def _featurize_requests(self, reqs):
        now = time.time()
        sources = ["cluster", "js", "github", "commoncrawl", "history", "seed"]
        def src_vec(src):
            v = [0]*len(sources)
            try:
                v[sources.index((src or "").lower())] = 1
            except ValueError:
                pass
            return v

        rows = []
        for r in reqs:
            depth = float(getattr(r, "depth", 0))
            s_static = float(getattr(r, "static_score", 0.0))
            s_dyn = float(getattr(r, "dynamic_score", 0.0))
            ts = float(getattr(r, "discovered_ts", 0))
            age = max(0.0, now - ts) / 3600.0 
            url = (getattr(r, "url", "") or "").lower()
            f_admin = 1.0 if "admin" in url else 0.0
            f_api = 1.0 if "/api" in url else 0.0
            f_graphql = 1.0 if "graphql" in url or "/gql" in url else 0.0
            f_ver = 1.0 if "/v1" in url or "/v2" in url or "/v3" in url else 0.0
            l_depth = math.log1p(depth)
            l_age = math.log1p(age)
            row = [
                l_depth, s_static/100.0, s_dyn/100.0, l_age,
                f_admin, f_api, f_graphql, f_ver,
                1.0,
            ] + src_vec(getattr(r, "source", ""))
            rows.append(row)
        X = np.array(rows, dtype=np.float32)
        if X.shape[1] < self.in_dim:
            pad = np.zeros((X.shape[0], self.in_dim - X.shape[1]), dtype=np.float32)
            X = np.concatenate([X, pad], axis=1)
        elif X.shape[1] > self.in_dim:
            X = X[:, :self.in_dim]
        return X

    def _build_graph(self, feats: np.ndarray):
        if not (_HAVE_TORCH and _HAVE_PYG):
            raise RuntimeError("torch_geometric not available")
        X = torch.from_numpy(feats).float()
        x_norm = torch.nn.functional.normalize(X, p=2, dim=1)
        sim = x_norm @ x_norm.T
        idx_i, idx_j = torch.where((sim > 0.90) & (torch.eye(sim.size(0)) == 0))
        if idx_i.numel() == 0:
            idx_i = torch.arange(0, X.size(0)-1, dtype=torch.long)
            idx_j = torch.arange(1, X.size(0), dtype=torch.long)
        edge_index = torch.stack([idx_i, idx_j], dim=0)
        return GeometricData(x=X, edge_index=edge_index)

    def _heuristic_score(self, r):
        score = 0.0
        sstat = float(getattr(r, "static_score", 0.0))
        sdyn = float(getattr(r, "dynamic_score", 0.0))
        depth = float(getattr(r, "depth", 0))
        url = (getattr(r, "url", "") or "").lower()
        score += 0.6*(sdyn/100.0) + 0.3*(sstat/100.0) - 0.05*max(0.0, depth-2)
        if "/api" in url: score += 0.15
        if "admin" in url: score += 0.20
        if "graphql" in url or "/gql" in url: score += 0.10
        return float(max(0.0, min(1.0, score)))


def serve(host: str = "[::]:50051", workers: int = 16):
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
    rpc.add_AdaptiveEngineServicer_to_server(AdaptiveEngine(), srv)
    srv.add_insecure_port(host)
    srv.start()
    srv.wait_for_termination()


if __name__ == '__main__':
    serve()
