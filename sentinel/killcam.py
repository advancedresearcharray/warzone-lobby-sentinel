"""Killcam video analysis — aim snap / jerk detection via frame motion."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class KillcamAnalysis:
    path: str
    frames_analyzed: int
    snap_velocity_p99: float
    jerk_variance: float
    aimbot_probability: float
    detail: str


def analyze_killcam(video_path: Path, sample_every: int = 2) -> KillcamAnalysis:
    """
    Analyze crosshair/camera motion in a killcam clip.
    Uses optical flow magnitude as proxy for view rotation speed.
    """
    import cv2
    import numpy as np

    cap = cv2.VideoCapture(str(video_path))
    if not cap.isOpened():
        raise FileNotFoundError(f"Cannot open video: {video_path}")

    ret, prev = cap.read()
    if not ret:
        raise ValueError("Empty video")

    prev_gray = cv2.cvtColor(prev, cv2.COLOR_BGR2GRAY)
    velocities: list[float] = []
    frame_idx = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame_idx += 1
        if frame_idx % sample_every != 0:
            continue

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        flow = cv2.calcOpticalFlowFarneback(
            prev_gray, gray, None, 0.5, 3, 15, 3, 5, 1.2, 0
        )
        mag, _ = cv2.cartToPolar(flow[..., 0], flow[..., 1])
        velocities.append(float(np.percentile(mag, 95)))
        prev_gray = gray

    cap.release()

    if len(velocities) < 5:
        return KillcamAnalysis(
            path=str(video_path),
            frames_analyzed=len(velocities),
            snap_velocity_p99=0.0,
            jerk_variance=0.0,
            aimbot_probability=0.0,
            detail="Not enough frames",
        )

    arr = np.array(velocities, dtype=np.float64)
    snap_p99 = float(np.percentile(arr, 99))
    # Jerk = derivative of velocity; low variance = robotic aim.
    accel = np.diff(arr)
    jerk = np.diff(accel) if len(accel) > 1 else np.array([0.0])
    jerk_var = float(np.var(jerk)) if len(jerk) else 0.0

    # Heuristic probability — calibrate against your own legit clips.
    snap_signal = min(1.0, snap_p99 / 8.0)
    smooth_signal = 1.0 - min(1.0, jerk_var / 0.05) if jerk_var < 0.05 else 0.0
    aim_prob = min(1.0, snap_signal * 0.65 + smooth_signal * 0.35)

    detail = f"p99_flow={snap_p99:.2f}, jerk_var={jerk_var:.4f}"
    return KillcamAnalysis(
        path=str(video_path),
        frames_analyzed=len(velocities),
        snap_velocity_p99=snap_p99,
        jerk_variance=jerk_var,
        aimbot_probability=aim_prob,
        detail=detail,
    )
