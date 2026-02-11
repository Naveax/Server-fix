use anyhow::Result;

#[cfg(any(test, all(feature = "torch_train_backend", not(debug_assertions))))]
use anyhow::Context;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
use clap::Parser;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
#[cfg(any(test, all(feature = "torch_train_backend", not(debug_assertions))))]
use std::path::Path;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
use std::path::PathBuf;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
use tch::nn::{self, Module, OptimizerConfig, RNN};
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
use tch::{CModule, Device, Kind, Reduction, Tensor};

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const SEQ_LEN: i64 = 10;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const FEATURE_DIM: i64 = 3;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const HIDDEN_DIM: i64 = 64;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const DEFAULT_EVAL_THRESHOLD: f64 = 0.5;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const THRESHOLD_CANDIDATES: &[f64] = &[0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90];
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const PACKET_COUNT_SCALE: f32 = 1_024.0;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const SIZE_AVG_SCALE: f32 = 1_500.0;
#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
const DELTA_SCALE: f32 = 1_024.0;

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
#[derive(Debug, Parser, Clone)]
#[command(name = "train")]
#[command(about = "Train and export a TorchScript LSTM anomaly model for nx_proxy")]
struct Args {
    #[arg(long, default_value_t = 1_000)]
    samples: usize,
    #[arg(long, default_value_t = 0.5)]
    anomaly_ratio: f64,
    #[arg(long, default_value_t = 80)]
    epochs: usize,
    #[arg(long, default_value_t = 64)]
    batch_size: usize,
    #[arg(long, default_value_t = 1e-3)]
    learning_rate: f64,
    #[arg(long, default_value_t = 7)]
    seed: u64,
    #[arg(long, default_value = "anomaly_model.pt")]
    output: PathBuf,
    #[arg(long)]
    roc_plot_output: Option<PathBuf>,
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
#[derive(Debug)]
struct LstmAnomalyNet {
    lstm: nn::LSTM,
    head: nn::Linear,
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
#[derive(Debug, Clone, Copy)]
struct EvalMetrics {
    loss: f64,
    accuracy: f64,
    precision: f64,
    recall: f64,
    f1: f64,
    best_threshold: f64,
    best_f1: f64,
    best_roc_threshold: f64,
    best_roc_j: f64,
    auc: f64,
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
impl LstmAnomalyNet {
    fn new(vs: &nn::Path<'_>) -> Self {
        let lstm = nn::lstm(vs / "lstm", FEATURE_DIM, HIDDEN_DIM, Default::default());
        let head = nn::linear(vs / "head", HIDDEN_DIM, 1, Default::default());
        Self { lstm, head }
    }

    fn forward_logits(&self, xs: &Tensor) -> Tensor {
        let (sequence_out, _state) = self.lstm.seq(xs);
        let last_step = sequence_out.select(1, SEQ_LEN - 1);
        self.head.forward(&last_step).squeeze_dim(-1)
    }

    fn forward_probs(&self, xs: &Tensor) -> Tensor {
        self.forward_logits(xs).sigmoid()
    }
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn main() -> Result<()> {
    let args = Args::parse();
    train_and_export(args)
}

#[cfg(any(not(feature = "torch_train_backend"), debug_assertions))]
fn main() -> Result<()> {
    anyhow::bail!(
        "`train` requires a libtorch-enabled release build. Run with: \
         cargo run -p nx_proxy --release --features torch_train --bin train -- --samples 1000 --output anomaly_model.pt \
         (or --features torch_train_full for native libtorch mode)"
    )
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn train_and_export(args: Args) -> Result<()> {
    let device = preferred_device();
    let mut rng = StdRng::seed_from_u64(args.seed);
    let sample_count = args.samples.max(2);
    let batch_size = args.batch_size.max(1) as i64;

    let anomaly_ratio = args.anomaly_ratio.clamp(0.05, 0.95);
    let (features, labels) =
        build_synthetic_dataset(sample_count, anomaly_ratio, &mut rng, device)?;

    let mut vs = nn::VarStore::new(device);
    let net = LstmAnomalyNet::new(&vs.root());
    let mut optimizer = nn::Adam::default().build(&vs, args.learning_rate)?;

    let sample_count_i64 = sample_count as i64;
    for epoch in 1..=args.epochs {
        let mut indices = (0..sample_count_i64).collect::<Vec<i64>>();
        indices.shuffle(&mut rng);
        let mut epoch_loss_sum = 0.0_f64;
        let mut epoch_batches = 0usize;
        for batch in indices.chunks(batch_size as usize) {
            let idx = Tensor::from_slice(batch)
                .to_kind(Kind::Int64)
                .to_device(device);
            let batch_x = features.index_select(0, &idx);
            let batch_y = labels.index_select(0, &idx);

            let logits = net.forward_logits(&batch_x);
            let loss = logits.binary_cross_entropy_with_logits::<Tensor>(
                &batch_y,
                None,
                None,
                Reduction::Mean,
            );
            epoch_loss_sum += loss.double_value(&[]);
            epoch_batches = epoch_batches.saturating_add(1);
            optimizer.backward_step_clip(&loss, 1.0);
        }

        if epoch == 1 || epoch % 5 == 0 || epoch == args.epochs {
            let train_loss = epoch_loss_sum / (epoch_batches.max(1) as f64);
            let eval = evaluate(&net, &features, &labels);
            println!(
                "epoch={epoch:>3} train_loss={train_loss:.4} eval_loss={:.4} accuracy={:.2}% precision={:.4} recall={:.4} f1={:.4} best_f1={:.4}@th={:.2} best_roc_j={:.4}@th={:.2} auc={:.4}",
                eval.loss,
                eval.accuracy * 100.0,
                eval.precision,
                eval.recall,
                eval.f1,
                eval.best_f1,
                eval.best_threshold,
                eval.best_roc_j,
                eval.best_roc_threshold,
                eval.auc
            );
        }
    }

    // Freeze before tracing so the exported module runs inference-only.
    vs.freeze();
    let trace_input = Tensor::zeros([1, SEQ_LEN, FEATURE_DIM], (Kind::Float, device));
    let mut closure = |inputs: &[Tensor]| vec![net.forward_probs(&inputs[0])];
    let module =
        CModule::create_by_tracing("NxAnomalyLstm", "forward", &[trace_input], &mut closure)
            .context("failed to trace LSTM model into TorchScript")?;
    module.save(&args.output).with_context(|| {
        format!(
            "failed saving TorchScript model to {}",
            args.output.display()
        )
    })?;
    if let Some(path) = &args.roc_plot_output {
        let roc_points = evaluate_roc_points(&net, &features, &labels);
        write_roc_svg(&roc_points, path)
            .with_context(|| format!("failed writing ROC plot to {}", path.display()))?;
    }

    println!(
        "export complete: samples={} anomaly_ratio={:.2} device={:?} epochs={} output={}",
        sample_count,
        anomaly_ratio,
        device,
        args.epochs,
        args.output.display()
    );
    Ok(())
}

#[cfg(all(
    feature = "torch_train_backend",
    not(debug_assertions),
    feature = "cuda_anomaly"
))]
fn preferred_device() -> Device {
    if tch::Cuda::is_available() {
        Device::Cuda(0)
    } else {
        Device::Cpu
    }
}

#[cfg(all(
    feature = "torch_train_backend",
    not(debug_assertions),
    not(feature = "cuda_anomaly")
))]
fn preferred_device() -> Device {
    Device::Cpu
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn build_synthetic_dataset(
    sample_count: usize,
    anomaly_ratio: f64,
    rng: &mut StdRng,
    device: Device,
) -> Result<(Tensor, Tensor)> {
    let anomaly_count = anomaly_count_for(sample_count, anomaly_ratio);

    let mut rows = Vec::with_capacity(sample_count);
    for _ in 0..(sample_count - anomaly_count) {
        rows.push((synthetic_normal_sequence(rng), 0.0_f32));
    }
    for _ in 0..anomaly_count {
        let sequence = match rng.gen_range(0..3) {
            0 => synthetic_spike_sequence(rng),
            1 => synthetic_flood_sequence(rng),
            _ => synthetic_ramp_sequence(rng),
        };
        rows.push((sequence, 1.0_f32));
    }
    rows.shuffle(rng);

    let mut feature_values =
        Vec::with_capacity(sample_count * (SEQ_LEN as usize) * (FEATURE_DIM as usize));
    let mut labels = Vec::with_capacity(sample_count);
    for (sequence, label) in rows {
        feature_values.extend(sequence);
        labels.push(label);
    }

    let features = Tensor::f_from_slice(&feature_values)
        .context("failed to build feature tensor from synthetic dataset")?
        .reshape([sample_count as i64, SEQ_LEN, FEATURE_DIM])
        .to_kind(Kind::Float)
        .to_device(device);
    let labels = Tensor::f_from_slice(&labels)
        .context("failed to build label tensor from synthetic dataset")?
        .reshape([sample_count as i64])
        .to_kind(Kind::Float)
        .to_device(device);

    Ok((features, labels))
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn synthetic_normal_sequence(rng: &mut StdRng) -> Vec<f32> {
    let mut out = Vec::with_capacity((SEQ_LEN as usize) * (FEATURE_DIM as usize));
    let mut prev_pps = rng.gen_range(10.0_f32..45.0_f32);
    for _ in 0..SEQ_LEN as usize {
        let packet_count = (prev_pps + rng.gen_range(-6.0_f32..8.0_f32)).max(1.0);
        let size_avg = rng.gen_range(220.0_f32..900.0_f32);
        let delta = packet_count - prev_pps + rng.gen_range(-6.0_f32..6.0_f32);
        prev_pps = packet_count;
        out.extend(normalize_step([packet_count, size_avg, delta]));
    }
    out
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn synthetic_spike_sequence(rng: &mut StdRng) -> Vec<f32> {
    let mut out = Vec::with_capacity((SEQ_LEN as usize) * (FEATURE_DIM as usize));
    let mut prev_pps = rng.gen_range(12.0_f32..40.0_f32);
    for step in 0..SEQ_LEN as usize {
        let spike_phase = step >= 7;
        let packet_count = if spike_phase {
            rng.gen_range(280.0_f32..1_600.0_f32)
        } else {
            (prev_pps + rng.gen_range(-5.0_f32..10.0_f32)).max(1.0)
        };
        let size_avg = if spike_phase {
            rng.gen_range(850.0_f32..1_400.0_f32)
        } else {
            rng.gen_range(250.0_f32..920.0_f32)
        };
        let surge = if spike_phase {
            rng.gen_range(80.0_f32..900.0_f32)
        } else {
            rng.gen_range(-10.0_f32..12.0_f32)
        };
        let delta = packet_count - prev_pps + surge;
        prev_pps = packet_count;
        out.extend(normalize_step([packet_count, size_avg, delta]));
    }
    out
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn synthetic_flood_sequence(rng: &mut StdRng) -> Vec<f32> {
    let mut out = Vec::with_capacity((SEQ_LEN as usize) * (FEATURE_DIM as usize));
    let mut prev_pps = rng.gen_range(700.0_f32..1_100.0_f32);
    for _ in 0..SEQ_LEN as usize {
        let packet_count = rng.gen_range(900.0_f32..2_000.0_f32);
        let size_avg = rng.gen_range(900.0_f32..1_400.0_f32);
        let delta = packet_count - prev_pps + rng.gen_range(40.0_f32..360.0_f32);
        prev_pps = packet_count;
        out.extend(normalize_step([packet_count, size_avg, delta]));
    }
    out
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn synthetic_ramp_sequence(rng: &mut StdRng) -> Vec<f32> {
    let mut out = Vec::with_capacity((SEQ_LEN as usize) * (FEATURE_DIM as usize));
    let mut prev_pps = rng.gen_range(20.0_f32..60.0_f32);
    for step in 0..SEQ_LEN as usize {
        let ramp = (step as f32 + 1.0) * rng.gen_range(20.0_f32..90.0_f32);
        let packet_count = (prev_pps + ramp + rng.gen_range(-8.0_f32..14.0_f32)).max(1.0);
        let size_avg = rng.gen_range(400.0_f32..1_250.0_f32);
        let delta = packet_count - prev_pps + rng.gen_range(15.0_f32..140.0_f32);
        prev_pps = packet_count;
        out.extend(normalize_step([packet_count, size_avg, delta]));
    }
    out
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn normalize_step(step: [f32; 3]) -> [f32; 3] {
    [
        (step[0] / PACKET_COUNT_SCALE).clamp(0.0, 8.0),
        (step[1] / SIZE_AVG_SCALE).clamp(0.0, 2.0),
        (step[2] / DELTA_SCALE).clamp(-8.0, 8.0),
    ]
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn evaluate(net: &LstmAnomalyNet, features: &Tensor, labels: &Tensor) -> EvalMetrics {
    let logits = net.forward_logits(features);
    let loss =
        logits.binary_cross_entropy_with_logits::<Tensor>(labels, None, None, Reduction::Mean);
    let probs = logits.sigmoid();
    let preds = probs
        .ge(DEFAULT_EVAL_THRESHOLD)
        .to_kind(Kind::Float)
        .to_device(labels.device());
    let ones = Tensor::ones_like(labels);

    let (tp, fp, fn_, tn) = confusion_counts(&preds, labels, &ones);
    let (precision, recall, f1) = precision_recall_f1(tp, fp, fn_);
    let accuracy = accuracy_from_counts(tp, fp, fn_, tn);

    let mut best_threshold = DEFAULT_EVAL_THRESHOLD;
    let mut best_f1 = f1;
    let mut best_roc_threshold = DEFAULT_EVAL_THRESHOLD;
    let mut best_roc_j = f64::NEG_INFINITY;
    for threshold in THRESHOLD_CANDIDATES {
        let preds = probs
            .ge(*threshold)
            .to_kind(Kind::Float)
            .to_device(labels.device());
        let (tp, fp, fn_, tn) = confusion_counts(&preds, labels, &ones);
        let (_precision, _recall, candidate_f1) = precision_recall_f1(tp, fp, fn_);
        if candidate_f1 > best_f1 {
            best_f1 = candidate_f1;
            best_threshold = *threshold;
        }
        let tpr = safe_ratio(tp, tp + fn_);
        let fpr = safe_ratio(fp, fp + tn);
        let youden_j = tpr - fpr;
        if youden_j > best_roc_j {
            best_roc_j = youden_j;
            best_roc_threshold = *threshold;
        }
    }
    let roc_points = roc_points_from_probs(&probs, labels, &ones);
    let auc = roc_auc(&roc_points);
    EvalMetrics {
        loss: loss.double_value(&[]),
        accuracy,
        precision,
        recall,
        f1,
        best_threshold,
        best_f1,
        best_roc_threshold,
        best_roc_j,
        auc,
    }
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn evaluate_roc_points(
    net: &LstmAnomalyNet,
    features: &Tensor,
    labels: &Tensor,
) -> Vec<(f64, f64)> {
    let probs = net.forward_logits(features).sigmoid();
    let ones = Tensor::ones_like(labels);
    roc_points_from_probs(&probs, labels, &ones)
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn roc_points_from_probs(probs: &Tensor, labels: &Tensor, ones: &Tensor) -> Vec<(f64, f64)> {
    let mut roc_points = vec![(0.0_f64, 0.0_f64)];
    for threshold in THRESHOLD_CANDIDATES {
        let preds = probs
            .ge(*threshold)
            .to_kind(Kind::Float)
            .to_device(labels.device());
        let (tp, fp, fn_, tn) = confusion_counts(&preds, labels, ones);
        let tpr = safe_ratio(tp, tp + fn_);
        let fpr = safe_ratio(fp, fp + tn);
        roc_points.push((fpr, tpr));
    }
    roc_points.push((1.0, 1.0));
    roc_points.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    roc_points
}

#[cfg(any(test, all(feature = "torch_train_backend", not(debug_assertions))))]
fn write_roc_svg(points: &[(f64, f64)], path: &Path) -> Result<()> {
    const WIDTH: f64 = 640.0;
    const HEIGHT: f64 = 480.0;
    const MARGIN: f64 = 48.0;
    let chart_w = WIDTH - (2.0 * MARGIN);
    let chart_h = HEIGHT - (2.0 * MARGIN);

    let mut polyline_points = String::new();
    for &(fpr, tpr) in points {
        let x = MARGIN + fpr.clamp(0.0, 1.0) * chart_w;
        let y = HEIGHT - MARGIN - tpr.clamp(0.0, 1.0) * chart_h;
        polyline_points.push_str(&format!("{x:.2},{y:.2} "));
    }

    let diagonal = format!(
        "{:.2},{:.2} {:.2},{:.2}",
        MARGIN,
        HEIGHT - MARGIN,
        WIDTH - MARGIN,
        MARGIN
    );
    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{WIDTH}\" height=\"{HEIGHT}\" viewBox=\"0 0 {WIDTH} {HEIGHT}\">\
<rect x=\"0\" y=\"0\" width=\"{WIDTH}\" height=\"{HEIGHT}\" fill=\"#ffffff\"/>\
<line x1=\"{m}\" y1=\"{h1}\" x2=\"{w1}\" y2=\"{h1}\" stroke=\"#111827\" stroke-width=\"1\"/>\
<line x1=\"{m}\" y1=\"{h1}\" x2=\"{m}\" y2=\"{m}\" stroke=\"#111827\" stroke-width=\"1\"/>\
<polyline points=\"{diag}\" fill=\"none\" stroke=\"#9ca3af\" stroke-width=\"1\" stroke-dasharray=\"4 4\"/>\
<polyline points=\"{pts}\" fill=\"none\" stroke=\"#1d4ed8\" stroke-width=\"2\"/>\
<text x=\"{label_x}\" y=\"{label_y}\" font-size=\"12\" fill=\"#111827\">ROC Curve</text>\
</svg>",
        m = MARGIN,
        h1 = HEIGHT - MARGIN,
        w1 = WIDTH - MARGIN,
        diag = diagonal,
        pts = polyline_points.trim_end(),
        label_x = MARGIN,
        label_y = MARGIN - 12.0
    );
    std::fs::write(path, svg)
        .with_context(|| format!("unable to write roc svg to {}", path.display()))?;
    Ok(())
}

#[cfg(any(test, all(feature = "torch_train_backend", not(debug_assertions))))]
fn anomaly_count_for(sample_count: usize, anomaly_ratio: f64) -> usize {
    let requested = ((sample_count as f64) * anomaly_ratio).round() as usize;
    requested.clamp(1, sample_count.saturating_sub(1))
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn safe_ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator > 0.0 {
        numerator / denominator
    } else {
        0.0
    }
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn confusion_counts(preds: &Tensor, labels: &Tensor, ones: &Tensor) -> (f64, f64, f64, f64) {
    let tp = (preds * labels).sum(Kind::Float).double_value(&[]);
    let fp = (preds * (ones - labels)).sum(Kind::Float).double_value(&[]);
    let fn_ = ((ones - preds) * labels).sum(Kind::Float).double_value(&[]);
    let tn = ((ones - preds) * (ones - labels))
        .sum(Kind::Float)
        .double_value(&[]);
    (tp, fp, fn_, tn)
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn precision_recall_f1(tp: f64, fp: f64, fn_: f64) -> (f64, f64, f64) {
    let precision = safe_ratio(tp, tp + fp);
    let recall = safe_ratio(tp, tp + fn_);
    let f1 = if (precision + recall) > 0.0 {
        (2.0 * precision * recall) / (precision + recall)
    } else {
        0.0
    };
    (precision, recall, f1)
}

#[cfg(all(feature = "torch_train_backend", not(debug_assertions)))]
fn accuracy_from_counts(tp: f64, fp: f64, fn_: f64, tn: f64) -> f64 {
    safe_ratio(tp + tn, tp + fp + fn_ + tn)
}

#[cfg(any(test, all(feature = "torch_train_backend", not(debug_assertions))))]
fn roc_auc(points: &[(f64, f64)]) -> f64 {
    if points.len() < 2 {
        return 0.0;
    }
    let mut auc = 0.0;
    for segment in points.windows(2) {
        let (x0, y0) = segment[0];
        let (x1, y1) = segment[1];
        let width = (x1 - x0).max(0.0);
        auc += width * (y0 + y1) * 0.5;
    }
    auc.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::{anomaly_count_for, roc_auc, write_roc_svg};
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn anomaly_count_is_bounded() {
        assert_eq!(anomaly_count_for(10, 0.0), 1);
        assert_eq!(anomaly_count_for(10, 1.0), 9);
    }

    #[test]
    fn anomaly_count_tracks_ratio() {
        assert_eq!(anomaly_count_for(1000, 0.5), 500);
        assert_eq!(anomaly_count_for(1000, 0.2), 200);
    }

    #[test]
    fn roc_plot_validation() {
        let roc_points = vec![(0.0, 0.0), (0.1, 0.5), (0.3, 0.8), (1.0, 1.0)];
        let auc = roc_auc(&roc_points);
        let expected_auc = 0.785_f64;
        assert!(
            (auc - expected_auc).abs() < 1e-9,
            "auc mismatch: got {auc}, expected {expected_auc}"
        );

        let temp = tempdir().expect("create temp dir for roc svg");
        let out = temp.path().join("roc_curve.svg");
        let output_path = out.to_string_lossy().to_string();
        write_roc_svg(&roc_points, &out).expect("write roc svg");
        assert!(out.exists(), "roc svg was not created");
        assert!(Path::new(&output_path).exists(), "roc svg path is missing");
        let content = fs::read_to_string(&out).expect("read roc svg");
        assert!(content.contains("<svg"), "svg header missing");
        assert!(content.contains("polyline"), "svg polyline missing");
    }
}
