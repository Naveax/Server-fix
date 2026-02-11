# RocketLeagueServerFix

Defensive UDP edge mitigation layer and guard components for operator-owned game server deployments.

## Scope
- Provides a vendor-agnostic UDP mitigation/proxy path (`nx_proxy`) with rate limiting, queue backpressure, and optional challenge/cookie gating.
- Includes supporting guard/tooling components in this workspace.
- Intended for deployment by server operators on infrastructure they control.

## Threat Model
- Volumetric DDoS ve server lag mitigation odaklıdır; ani UDP paket patlamalarında servis sürekliliğini korumayı hedefler.
- Epic netcode/server optimizasyon eksikliği kaynaklı volumetrik yüklerde outage riskine karşı operatör tarafında savunma katmanı sağlar.
- Uygulanan kontroller: per-IP token bucket, bounded queues, anomaly scoring (heuristic/Torch model).
- Daha gelişmiş model isteyen operatörler için TorchScript LSTM/autoencoder modelini `anomaly.model = "torch"` ve `anomaly.torch_model_path` ile bağlayabilir.

## Out Of Scope
- Patching or controlling third-party ranked/matchmaking infrastructure.
- Offensive tooling, attack simulation against third-party services, or exploit development.

## Quick Start

### Rust Workspace
```bash
cargo build --workspace
cargo test --all
```

Run the UDP proxy:
```bash
cargo run -p nx_proxy -- --config config/dev.toml
```

### CMake Guard Build
```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Direct test binaries:
```bash
./build/guard_tests
./build/guard_property_tests
```

## Configuration
- `config/example.toml`: safer production-oriented template.
- `config/dev.toml`: local development defaults.
- DDoS token bucket shortcut: `[rate_limit].ddos_limit = 500.0` (alias for per-IP packets/sec).
- Spike detection: `[anomaly]` section with `enabled`, `anomaly_threshold`, and `model`.

Example:
```bash
cargo run -p nx_proxy -- --config config/example.toml
```

Local flood simulation (authorized local testing only):
```bash
cargo run -p nx_proxy --bin nx_flood_sim -- --target 127.0.0.1:7000 --pps 10000 --duration-secs 5
```

Train/export TorchScript LSTM anomaly model (`[1,10,3] -> hidden 64 -> sigmoid`):
```bash
cargo run -p nx_proxy --release --features torch_train --bin train -- --samples 1000 --anomaly-ratio 0.5 --output anomaly_model.pt --roc-plot-output roc_curve.svg
```
Native libtorch modu (opt-in):
```bash
cargo run -p nx_proxy --release --features torch_train_full,cuda_anomaly --bin train -- --samples 1000 --output anomaly_model.pt --roc-plot-output roc_curve.svg
```
Not: `torch_train` CI-stable doc-only modudur. Native mod için libtorch kurulumu gerekir (`LIBTORCH` ortam değişkeni).

### Libtorch Full Export Kurulumu
```bash
export LIBTORCH=/path/to/libtorch
# alternatif: Python kurulumundan kullanmak icin
export LIBTORCH_USE_PYTORCH=1
cargo run -p nx_proxy --release --features torch_train_full,cuda_anomaly --bin train -- --samples 1000 --output anomaly_model.pt --roc-plot-output roc_curve.svg
```

### CUDA Icin Libtorch Kurulumu
```bash
export LIBTORCH=/path/to/libtorch-cuda
export LD_LIBRARY_PATH="$LIBTORCH/lib:${LD_LIBRARY_PATH}"
cargo run -p nx_proxy --release --features torch_train_full,cuda_anomaly --bin train -- --samples 1000 --output anomaly_model.pt --roc-plot-output roc_curve.svg
```

Egitim ciktisi `train_loss`, `eval_loss`, `accuracy`, `precision`, `recall`, `f1`, `best_f1@threshold`, `best_roc_j@threshold` ve `auc` metriklerini yazdirir.
Bench ciktisi `anomaly_latency_p50/p99_thresh_*`, `anomaly_drop_ratio_thresh_*`, `anomaly_auc_thresh_*`, `anomaly_drop_ratio_vs_auc_thresh_*`, threshold delta satirlari ve CUDA aciksa `anomaly_latency_cuda_*_thresh_*` metriklerini de raporlar.

Ornek (yerel synthetic bench, degerler ortama gore degisir):
- `thresh 0.5` (CPU): `drop_ratio=0.9997`, `p99=248.08us`
- `thresh 0.7` (CUDA): `drop_ratio=0.9997`, `p99=212.64us`

### Benchmark Karsilastirma Sablonu
- `proxy_enabled`: `anomaly_drop_ratio_thresh_*`, `anomaly_latency_p99_thresh_*`
- `baseline_path`: ayni trafik profili altinda p50/p99 gecikme ve drop metrikleri
- `delta`: `*_delta_thresh_*` satirlariyla threshold etkisini karsilastirin.
- Karsilastirmalari yalnizca kendi ortaminizda olctugunuz verilerle raporlayin.

## Security Note
Use this project only on systems and networks you own or are explicitly authorized to operate. Do not run abuse/flood testing against third-party infrastructure.

## Documentation
- Build notes: `docs/Build.md`
- Architecture: `docs/ARCHITECTURE.md`
- Deployment: `docs/DEPLOYMENT.md`
