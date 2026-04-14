"use client";

import { useEffect, useRef, useState } from "react";

interface TrustScoreGaugeProps {
  score: number;
  size?: number;
  animated?: boolean;
}

function scoreZoneColor(score: number): string {
  if (score <= 34) return "#f85149";
  if (score <= 54) return "#fb923c";
  if (score <= 74) return "#f59e0b";
  if (score <= 89) return "#0080ff";
  return "#00c853";
}

function scoreLabel(score: number): string {
  if (score <= 34) return "Critical Risk";
  if (score <= 54) return "High Risk";
  if (score <= 74) return "Moderate";
  if (score <= 89) return "Trusted";
  return "Exemplary";
}

export default function TrustScoreGauge({ score, size = 200, animated = true }: TrustScoreGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, score));
  const [displayScore, setDisplayScore] = useState(animated ? 0 : clampedScore);
  const animRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);

  useEffect(() => {
    if (!animated) {
      setDisplayScore(clampedScore);
      return;
    }
    const duration = 1200;
    const easeOut = (t: number) => 1 - Math.pow(1 - t, 3);

    const animate = (timestamp: number) => {
      if (!startRef.current) startRef.current = timestamp;
      const elapsed = timestamp - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      setDisplayScore(Math.round(easeOut(progress) * clampedScore));
      if (progress < 1) {
        animRef.current = requestAnimationFrame(animate);
      }
    };
    animRef.current = requestAnimationFrame(animate);
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
    };
  }, [clampedScore, animated]);

  const cx = size / 2;
  const cy = size / 2;
  const radius = size * 0.38;
  const strokeWidth = size * 0.055;

  // Arc spans 220 degrees: from 160deg to 380deg (clockwise)
  const startAngle = 160;
  const totalArc = 220;

  const toRad = (deg: number) => (deg * Math.PI) / 180;

  const arcPoint = (angle: number, r: number) => ({
    x: cx + Math.cos(toRad(angle)) * r,
    y: cy + Math.sin(toRad(angle)) * r,
  });

  const describeArc = (startDeg: number, endDeg: number, r: number) => {
    const s = arcPoint(startDeg, r);
    const e = arcPoint(endDeg, r);
    const largeArc = endDeg - startDeg > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
  };

  // Color zones as arc segments
  const zones = [
    { min: 0, max: 34, color: "#f85149" },
    { min: 35, max: 54, color: "#fb923c" },
    { min: 55, max: 74, color: "#f59e0b" },
    { min: 75, max: 89, color: "#0080ff" },
    { min: 90, max: 100, color: "#00c853" },
  ];

  // Track arc (grey background)
  const trackPath = describeArc(startAngle, startAngle + totalArc, radius);

  // Fill arc based on score
  const fillDeg = (displayScore / 100) * totalArc;
  const fillPath = fillDeg > 0 ? describeArc(startAngle, startAngle + fillDeg, radius) : null;
  const fillColor = scoreZoneColor(displayScore);

  // Needle
  const needleAngle = startAngle + (displayScore / 100) * totalArc;
  const needleLength = radius * 0.82;
  const needleTip = arcPoint(needleAngle, needleLength);
  const needleBase = arcPoint(needleAngle - 90, size * 0.025);
  const needleBase2 = arcPoint(needleAngle + 90, size * 0.025);

  // Zone tick marks
  const zoneTicks = [0, 35, 55, 75, 90, 100];

  const gradId = `gauge-grad-${score}`;

  return (
    <div style={{ display: "inline-block", position: "relative" }}>
      <svg width={size} height={size * 0.78} viewBox={`0 0 ${size} ${size * 0.78}`} fill="none">
        <defs>
          <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#f85149" />
            <stop offset="34%" stopColor="#fb923c" />
            <stop offset="55%" stopColor="#f59e0b" />
            <stop offset="75%" stopColor="#0080ff" />
            <stop offset="100%" stopColor="#00c853" />
          </linearGradient>
        </defs>

        {/* Track */}
        <path
          d={trackPath}
          stroke="var(--border-subtle, #1a1a1a)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          fill="none"
        />

        {/* Zone color segments (background reference) */}
        {zones.map((zone) => {
          const segStart = startAngle + (zone.min / 100) * totalArc;
          const segEnd = startAngle + ((zone.max + 0.5) / 100) * totalArc;
          return (
            <path
              key={zone.min}
              d={describeArc(segStart, segEnd, radius)}
              stroke={zone.color}
              strokeWidth={strokeWidth}
              strokeLinecap="butt"
              fill="none"
              strokeOpacity="0.15"
            />
          );
        })}

        {/* Fill arc */}
        {fillPath && (
          <path
            d={fillPath}
            stroke={fillColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            fill="none"
            style={{ transition: "stroke 0.3s ease" }}
          />
        )}

        {/* Zone boundary ticks */}
        {zoneTicks.map((val) => {
          const angle = startAngle + (val / 100) * totalArc;
          const inner = arcPoint(angle, radius - strokeWidth * 0.6);
          const outer = arcPoint(angle, radius + strokeWidth * 0.6);
          return (
            <line
              key={val}
              x1={inner.x}
              y1={inner.y}
              x2={outer.x}
              y2={outer.y}
              stroke="#0a0a0a"
              strokeWidth={size * 0.008}
            />
          );
        })}

        {/* Needle */}
        <polygon
          points={`${needleTip.x},${needleTip.y} ${needleBase.x},${needleBase.y} ${cx},${cy} ${needleBase2.x},${needleBase2.y}`}
          fill={fillColor}
          fillOpacity="0.9"
          style={{ transition: "fill 0.3s ease" }}
        />

        {/* Needle center dot */}
        <circle cx={cx} cy={cy} r={size * 0.04} fill="var(--bg-surface)" stroke={fillColor} strokeWidth={size * 0.012} />
        <circle cx={cx} cy={cy} r={size * 0.018} fill={fillColor} />

        {/* Score text */}
        <text
          x={cx}
          y={cy + radius * 0.62}
          textAnchor="middle"
          fontSize={size * 0.22}
          fontWeight="800"
          fontFamily="Inter, system-ui, sans-serif"
          fill={fillColor}
          style={{ transition: "fill 0.3s ease" }}
        >
          {displayScore}
        </text>

        {/* Score label */}
        <text
          x={cx}
          y={cy + radius * 0.62 + size * 0.07}
          textAnchor="middle"
          fontSize={size * 0.068}
          fontWeight="500"
          fontFamily="Inter, system-ui, sans-serif"
          fill="var(--text-muted)"
        >
          {scoreLabel(displayScore)}
        </text>

        {/* Min/max labels */}
        <text
          x={arcPoint(startAngle, radius + strokeWidth * 1.5).x}
          y={arcPoint(startAngle, radius + strokeWidth * 1.5).y + size * 0.02}
          textAnchor="middle"
          fontSize={size * 0.055}
          fill="var(--text-muted)"
          fontFamily="Inter, system-ui, sans-serif"
        >
          0
        </text>
        <text
          x={arcPoint(startAngle + totalArc, radius + strokeWidth * 1.5).x}
          y={arcPoint(startAngle + totalArc, radius + strokeWidth * 1.5).y + size * 0.02}
          textAnchor="middle"
          fontSize={size * 0.055}
          fill="var(--text-muted)"
          fontFamily="Inter, system-ui, sans-serif"
        >
          100
        </text>
      </svg>
    </div>
  );
}
