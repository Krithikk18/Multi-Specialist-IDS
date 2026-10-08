"""
Deep anomaly detectors for Stage 3, implemented with a minimal, dependency
-light PyTorch setup. Only imported if torch is available (see
stage3_models.get_anomaly_zoo). Each class exposes a small sklearn-like
API: fit(X), decision_function(X) (higher = more normal / less anomalous,
matching sklearn's IsolationForest convention), and predict(X) returning
{-1, 1} (-1 = outlier / candidate zero-day, 1 = inlier / known).
"""

import numpy as np

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None
    nn = None


def _to_tensor(X):
    arr = X.values if hasattr(X, "values") else np.asarray(X)
    return torch.tensor(arr, dtype=torch.float32)


class _MLP(nn.Module if nn else object):
    def __init__(self, in_dim, hidden_dims, out_dim):
        super().__init__()
        layers = []
        prev = in_dim
        for h in hidden_dims:
            layers += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        layers += [nn.Linear(prev, out_dim)]
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


class AutoencoderDetector:
    """Reconstruction-error-based anomaly detector: trains on known-class
    data only, flags high reconstruction error as anomalous (zero-day)."""

    def __init__(self, hidden_dims=(32, 16), bottleneck=8, epochs=30,
                 batch_size=256, lr=1e-3, random_state=42):
        self.hidden_dims = hidden_dims
        self.bottleneck = bottleneck
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.random_state = random_state
        self.threshold_ = None

    def fit(self, X, y=None):
        torch.manual_seed(self.random_state)
        X_t = _to_tensor(X)
        in_dim = X_t.shape[1]
        enc_dims = list(self.hidden_dims) + [self.bottleneck]
        dec_dims = list(reversed(self.hidden_dims))

        self.encoder = _MLP(in_dim, enc_dims[:-1], enc_dims[-1])
        self.decoder = _MLP(self.bottleneck, dec_dims, in_dim)

        params = list(self.encoder.parameters()) + list(self.decoder.parameters())
        opt = torch.optim.Adam(params, lr=self.lr)
        loss_fn = nn.MSELoss()

        n = X_t.shape[0]
        for epoch in range(self.epochs):
            perm = torch.randperm(n)
            for i in range(0, n, self.batch_size):
                idx = perm[i:i + self.batch_size]
                batch = X_t[idx]
                opt.zero_grad()
                z = self.encoder(batch)
                recon = self.decoder(z)
                loss = loss_fn(recon, batch)
                loss.backward()
                opt.step()

        with torch.no_grad():
            recon = self.decoder(self.encoder(X_t))
            errors = torch.mean((recon - X_t) ** 2, dim=1).numpy()
        self.threshold_ = np.percentile(errors, 95)  # ~5% contamination assumption
        return self

    def _reconstruction_error(self, X):
        X_t = _to_tensor(X)
        with torch.no_grad():
            recon = self.decoder(self.encoder(X_t))
            errors = torch.mean((recon - X_t) ** 2, dim=1).numpy()
        return errors

    def decision_function(self, X):
        # Higher = more normal (sklearn convention) -> negative error
        return -self._reconstruction_error(X)

    def predict(self, X):
        errors = self._reconstruction_error(X)
        return np.where(errors > self.threshold_, -1, 1)


class VAEDetector:
    """Variational Autoencoder anomaly detector using reconstruction loss
    (+ KL term during training only) as the anomaly score."""

    def __init__(self, hidden_dim=32, latent_dim=8, epochs=30,
                 batch_size=256, lr=1e-3, random_state=42):
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.random_state = random_state
        self.threshold_ = None

    def fit(self, X, y=None):
        torch.manual_seed(self.random_state)
        X_t = _to_tensor(X)
        in_dim = X_t.shape[1]

        self.enc_fc = nn.Linear(in_dim, self.hidden_dim)
        self.enc_mu = nn.Linear(self.hidden_dim, self.latent_dim)
        self.enc_logvar = nn.Linear(self.hidden_dim, self.latent_dim)
        self.dec_fc1 = nn.Linear(self.latent_dim, self.hidden_dim)
        self.dec_fc2 = nn.Linear(self.hidden_dim, in_dim)

        params = (list(self.enc_fc.parameters()) + list(self.enc_mu.parameters()) +
                  list(self.enc_logvar.parameters()) + list(self.dec_fc1.parameters()) +
                  list(self.dec_fc2.parameters()))
        opt = torch.optim.Adam(params, lr=self.lr)

        def encode(x):
            h = torch.relu(self.enc_fc(x))
            return self.enc_mu(h), self.enc_logvar(h)

        def reparam(mu, logvar):
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            return mu + eps * std

        def decode(z):
            h = torch.relu(self.dec_fc1(z))
            return self.dec_fc2(h)

        n = X_t.shape[0]
        for epoch in range(self.epochs):
            perm = torch.randperm(n)
            for i in range(0, n, self.batch_size):
                idx = perm[i:i + self.batch_size]
                batch = X_t[idx]
                opt.zero_grad()
                mu, logvar = encode(batch)
                z = reparam(mu, logvar)
                recon = decode(z)
                recon_loss = torch.mean((recon - batch) ** 2)
                kl_loss = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
                loss = recon_loss + 0.001 * kl_loss
                loss.backward()
                opt.step()

        self._encode = encode
        self._decode = decode
        with torch.no_grad():
            mu, logvar = encode(X_t)
            recon = decode(mu)  # use mean (no sampling) at inference
            errors = torch.mean((recon - X_t) ** 2, dim=1).numpy()
        self.threshold_ = np.percentile(errors, 95)
        return self

    def _reconstruction_error(self, X):
        X_t = _to_tensor(X)
        with torch.no_grad():
            mu, logvar = self._encode(X_t)
            recon = self._decode(mu)
            errors = torch.mean((recon - X_t) ** 2, dim=1).numpy()
        return errors

    def decision_function(self, X):
        return -self._reconstruction_error(X)

    def predict(self, X):
        errors = self._reconstruction_error(X)
        return np.where(errors > self.threshold_, -1, 1)


class DeepSVDDDetector:
    """Deep Support Vector Data Description: learns a neural mapping that
    pulls known-class data toward a fixed center c in latent space;
    distance from c at inference time is the anomaly score."""

    def __init__(self, hidden_dims=(32, 16), latent_dim=8, epochs=30,
                 batch_size=256, lr=1e-3, random_state=42):
        self.hidden_dims = hidden_dims
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.random_state = random_state
        self.threshold_ = None
        self.center_ = None

    def fit(self, X, y=None):
        torch.manual_seed(self.random_state)
        X_t = _to_tensor(X)
        in_dim = X_t.shape[1]

        self.net = _MLP(in_dim, list(self.hidden_dims), self.latent_dim)

        # Initialize center as the mean of an initial forward pass
        # (standard DeepSVDD initialization trick), with a small epsilon
        # floor to avoid collapsing dimensions to exactly zero.
        with torch.no_grad():
            init_out = self.net(X_t)
            c = init_out.mean(dim=0)
            c[(c.abs() < 1e-6)] = 1e-6
        self.center_ = c

        opt = torch.optim.Adam(self.net.parameters(), lr=self.lr)
        n = X_t.shape[0]
        for epoch in range(self.epochs):
            perm = torch.randperm(n)
            for i in range(0, n, self.batch_size):
                idx = perm[i:i + self.batch_size]
                batch = X_t[idx]
                opt.zero_grad()
                out = self.net(batch)
                dist = torch.sum((out - self.center_) ** 2, dim=1)
                loss = torch.mean(dist)
                loss.backward()
                opt.step()

        with torch.no_grad():
            out = self.net(X_t)
            dist = torch.sum((out - self.center_) ** 2, dim=1).numpy()
        self.threshold_ = np.percentile(dist, 95)
        return self

    def _distance(self, X):
        X_t = _to_tensor(X)
        with torch.no_grad():
            out = self.net(X_t)
            dist = torch.sum((out - self.center_) ** 2, dim=1).numpy()
        return dist

    def decision_function(self, X):
        return -self._distance(X)

    def predict(self, X):
        dist = self._distance(X)
        return np.where(dist > self.threshold_, -1, 1)
