//! 8196D→32D feature folding — orthogonal block projection for telemetry fingerprints.
//!
//! Inspired by dimensional folding (Kilpatrick, [Zenodo 18102374](https://zenodo.org/records/18102374)):
//! sparse high-dimensional telemetry is partitioned into 256 blocks of 32 features,
//! each block projected onto a shared 32-dimensional embedding via fixed orthogonal weights.
//! Lobby similarity runs in O(n) on 32-float vectors instead of full JSON snapshots.

pub const FOLD_DIM: usize = 32;
pub const SOURCE_DIM: usize = 8196;
pub const BLOCKS: usize = SOURCE_DIM / FOLD_DIM; // 256

/// Fixed orthogonal-ish projection weights (deterministic, no runtime cost).
fn block_weight(block: usize, dim: usize) -> f32 {
    // Walsh-like pattern: fast, bounded, decorrelated across blocks.
    let b = block as f32;
    let d = dim as f32;
    ((b * 0.6180339887 + d * 1.3247179572).sin() * 0.707106781).clamp(-1.0, 1.0)
}

/// Expand snapshot telemetry into a sparse 8196-vector, then fold to 32D.
pub fn fold_telemetry(
    conns: f32,
    wan: Option<f32>,
    mm_delta: Option<f32>,
    server_jitter: Option<f32>,
    wan_jitter: Option<f32>,
    role_counts: &[(u8, u16)], // (role_index, count)
    phase_code: u8,            // 0 idle, 1 bg, 2 mm, 3 match
    cheater_score: f32,
) -> [f32; FOLD_DIM] {
    let mut source = [0.0f32; SOURCE_DIM];

    // Core scalars occupy first block slots.
    source[0] = conns / 200.0;
    source[1] = wan.unwrap_or(0.0) / 150.0;
    source[2] = mm_delta.unwrap_or(0.0) / 100.0;
    source[3] = server_jitter.unwrap_or(0.0) / 50.0;
    source[4] = wan_jitter.unwrap_or(0.0) / 50.0;
    source[5] = phase_code as f32 / 3.0;
    source[6] = cheater_score;

    // Role sparsity pattern — hierarchical encoding (pattern framework).
    for (i, (role_idx, count)) in role_counts.iter().enumerate().take(24) {
        let slot = 32 + i * 2;
        source[slot] = *role_idx as f32 / 16.0;
        source[slot + 1] = (*count as f32).ln_1p() / 5.0;
    }

    // Periodicity hooks: sin/cos of conn magnitude (quadrant deduction proxy).
    source[128] = (conns * 0.1).sin();
    source[129] = (conns * 0.1).cos();
    if let Some(w) = wan {
        source[130] = (w * 0.05).sin();
        source[131] = (w * 0.05).cos();
    }

    fold_vector(&source)
}

pub fn fold_vector(source: &[f32; SOURCE_DIM]) -> [f32; FOLD_DIM] {
    let mut out = [0.0f32; FOLD_DIM];
    for block in 0..BLOCKS {
        let base = block * FOLD_DIM;
        for d in 0..FOLD_DIM {
            let w = block_weight(block, d);
            out[d] += source[base + d] * w;
        }
    }
    // L2 normalize for stable cosine similarity.
    let norm = out.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-6);
    for v in &mut out {
        *v /= norm;
    }
    out
}

pub fn cosine_similarity(a: &[f32; FOLD_DIM], b: &[f32; FOLD_DIM]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Compress folded lobby history with zstd (practical storage, not lossless exabyte claims).
pub fn compress_folds(folds: &[[f32; FOLD_DIM]]) -> Vec<u8> {
    let flat: Vec<f32> = folds.iter().flat_map(|f| f.iter().copied()).collect();
    let bytes: Vec<u8> = flat.iter().flat_map(|f| f.to_le_bytes()).collect();
    zstd::encode_all(bytes.as_slice(), 3).unwrap_or_default()
}

pub fn fold_to_b64(fold: &[f32; FOLD_DIM]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes: Vec<u8> = fold.iter().flat_map(|f| f.to_le_bytes()).collect();
    STANDARD.encode(bytes)
}

pub fn fold_from_b64(payload: &str) -> Option<[f32; FOLD_DIM]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = STANDARD.decode(payload.trim()).ok()?;
    if raw.len() < FOLD_DIM * 4 {
        return None;
    }
    let mut fold = [0.0f32; FOLD_DIM];
    for d in 0..FOLD_DIM {
        fold[d] = f32::from_le_bytes(raw[d * 4..d * 4 + 4].try_into().ok()?);
    }
    Some(fold)
}

pub fn decompress_folds(data: &[u8], count: usize) -> Vec<[f32; FOLD_DIM]> {
    let Ok(raw) = zstd::decode_all(data) else {
        return Vec::new();
    };
    if raw.len() < count * FOLD_DIM * 4 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut fold = [0.0f32; FOLD_DIM];
        for d in 0..FOLD_DIM {
            let off = (i * FOLD_DIM + d) * 4;
            fold[d] = f32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
        }
        out.push(fold);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_is_deterministic() {
        let a = fold_telemetry(80.0, Some(12.0), Some(30.0), None, None, &[(1, 5)], 2, 0.3);
        let b = fold_telemetry(80.0, Some(12.0), Some(30.0), None, None, &[(1, 5)], 2, 0.3);
        assert_eq!(a, b);
    }

    #[test]
    fn compress_roundtrip() {
        let f1 = fold_telemetry(50.0, Some(10.0), None, None, None, &[], 2, 0.1);
        let f2 = fold_telemetry(120.0, Some(15.0), Some(40.0), None, None, &[(2, 8)], 2, 0.6);
        let data = compress_folds(&[f1, f2]);
        let back = decompress_folds(&data, 2);
        assert_eq!(back.len(), 2);
        assert!((cosine_similarity(&back[0], &f1) - 1.0).abs() < 1e-5);
    }
}
