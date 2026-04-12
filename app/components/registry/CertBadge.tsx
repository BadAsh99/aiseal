import type { CertTier, CertStatus } from "../../../lib/registry";

interface CertBadgeProps {
  vendor_name: string;
  tier: CertTier;
  cert_id: string;
  status: CertStatus;
  score: number;
  size?: "sm" | "md" | "lg";
}

const TIER_CONFIG: Record<CertTier, {
  label: string;
  sublabel: string;
  primaryColor: string;
  secondaryColor: string;
  ringColor: string;
  gradient: [string, string];
}> = {
  "ACF-1": {
    label: "ACF-1",
    sublabel: "VERIFIED",
    primaryColor: "#9ca3af",
    secondaryColor: "#d1d5db",
    ringColor: "#6b7280",
    gradient: ["#4b5563", "#9ca3af"],
  },
  "ACF-2": {
    label: "ACF-2",
    sublabel: "ASSURED",
    primaryColor: "#0080ff",
    secondaryColor: "#60a5fa",
    ringColor: "#0080ff",
    gradient: ["#0044aa", "#0080ff"],
  },
  "ACF-3": {
    label: "ACF-3",
    sublabel: "CERTIFIED",
    primaryColor: "#d4a017",
    secondaryColor: "#fbbf24",
    ringColor: "#d4a017",
    gradient: ["#92400e", "#d4a017"],
  },
};

const STATUS_CONFIG: Record<CertStatus, {
  label: string;
  color: string;
  opacity: number;
}> = {
  ACTIVE: { label: "ACTIVE", color: "#00c853", opacity: 1 },
  UNDER_REVIEW: { label: "UNDER REVIEW", color: "#f59e0b", opacity: 1 },
  SUSPENDED: { label: "SUSPENDED", color: "#f85149", opacity: 0.6 },
  EXPIRED: { label: "EXPIRED", color: "#6b7280", opacity: 0.5 },
};

const SIZE_MAP = {
  sm: 100,
  md: 160,
  lg: 220,
};

export default function CertBadge({ vendor_name, tier, cert_id, status, score, size = "md" }: CertBadgeProps) {
  const tc = TIER_CONFIG[tier];
  const sc = STATUS_CONFIG[status];
  const dim = SIZE_MAP[size];
  const isInactive = status === "SUSPENDED" || status === "EXPIRED";
  const gradId = `badge-grad-${cert_id.replace(/[^a-z0-9]/gi, "")}`;
  const ringId = `badge-ring-${cert_id.replace(/[^a-z0-9]/gi, "")}`;
  const cx = dim / 2;
  const cy = dim / 2;
  const outerR = dim * 0.46;
  const innerR = dim * 0.38;
  const fontSize = {
    tier: dim * 0.12,
    sublabel: dim * 0.065,
    score: dim * 0.18,
    scoreLabel: dim * 0.055,
    vendor: dim * 0.055,
    status: dim * 0.05,
    certId: dim * 0.045,
  };

  return (
    <svg
      width={dim}
      height={dim}
      viewBox={`0 0 ${dim} ${dim}`}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ opacity: isInactive ? sc.opacity : 1 }}
    >
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={tc.gradient[0]} />
          <stop offset="100%" stopColor={tc.gradient[1]} />
        </linearGradient>
        <radialGradient id={ringId} cx="50%" cy="30%" r="70%">
          <stop offset="0%" stopColor={tc.secondaryColor} stopOpacity="0.3" />
          <stop offset="100%" stopColor={tc.primaryColor} stopOpacity="0.05" />
        </radialGradient>
        <filter id={`shadow-${cert_id.replace(/[^a-z0-9]/gi, "")}`}>
          <feDropShadow dx="0" dy="2" stdDeviation={dim * 0.025} floodColor={tc.primaryColor} floodOpacity="0.4" />
        </filter>
      </defs>

      {/* Outer ring background */}
      <circle cx={cx} cy={cy} r={outerR} fill={`url(#${ringId})`} stroke={tc.ringColor} strokeWidth={dim * 0.012} strokeOpacity="0.6" />

      {/* Tick marks on ring */}
      {Array.from({ length: 36 }, (_, i) => {
        const angle = (i * 10 - 90) * (Math.PI / 180);
        const isMajor = i % 9 === 0;
        const r1 = outerR - (isMajor ? dim * 0.04 : dim * 0.02);
        const r2 = outerR - dim * 0.005;
        return (
          <line
            key={i}
            x1={cx + Math.cos(angle) * r1}
            y1={cy + Math.sin(angle) * r1}
            x2={cx + Math.cos(angle) * r2}
            y2={cy + Math.sin(angle) * r2}
            stroke={tc.primaryColor}
            strokeWidth={isMajor ? dim * 0.008 : dim * 0.004}
            strokeOpacity={isMajor ? 0.8 : 0.3}
          />
        );
      })}

      {/* Inner filled circle */}
      <circle
        cx={cx}
        cy={cy}
        r={innerR}
        fill={`url(#${gradId})`}
        stroke={tc.primaryColor}
        strokeWidth={dim * 0.008}
        strokeOpacity="0.4"
        filter={isInactive ? undefined : `url(#shadow-${cert_id.replace(/[^a-z0-9]/gi, "")})`}
      />

      {/* Inner circle surface texture */}
      <circle cx={cx} cy={cy} r={innerR} fill="url(#ring-tex)" fillOpacity="0.08" />

      {/* Shield icon at top */}
      <g transform={`translate(${cx - dim * 0.055}, ${cy - innerR * 0.72}) scale(${dim * 0.0046})`}>
        <path
          d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
          fill={tc.secondaryColor}
          fillOpacity="0.25"
          stroke={tc.secondaryColor}
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
        <path
          d="M9 12L11 14L15 10"
          stroke={tc.secondaryColor}
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </g>

      {/* Tier label */}
      <text
        x={cx}
        y={cy - innerR * 0.28}
        textAnchor="middle"
        fontSize={fontSize.tier}
        fontWeight="900"
        fontFamily="Inter, system-ui, sans-serif"
        fill={tc.secondaryColor}
        letterSpacing="0.05em"
      >
        {tc.label}
      </text>

      {/* Score */}
      <text
        x={cx}
        y={cy + innerR * 0.12}
        textAnchor="middle"
        fontSize={fontSize.score}
        fontWeight="800"
        fontFamily="Inter, system-ui, sans-serif"
        fill="#ffffff"
      >
        {score}
      </text>

      {/* "TrustScore" under score */}
      <text
        x={cx}
        y={cy + innerR * 0.32}
        textAnchor="middle"
        fontSize={fontSize.scoreLabel}
        fontWeight="500"
        fontFamily="Inter, system-ui, sans-serif"
        fill={tc.primaryColor}
        fillOpacity="0.8"
        letterSpacing="0.06em"
      >
        TRUSTSCORE
      </text>

      {/* Sublabel (VERIFIED/ASSURED/CERTIFIED) */}
      <text
        x={cx}
        y={cy + innerR * 0.55}
        textAnchor="middle"
        fontSize={fontSize.sublabel}
        fontWeight="700"
        fontFamily="Inter, system-ui, sans-serif"
        fill={tc.secondaryColor}
        fillOpacity="0.7"
        letterSpacing="0.12em"
      >
        {tc.sublabel}
      </text>

      {/* Status bar at bottom of inner circle */}
      <rect
        x={cx - innerR * 0.7}
        y={cy + innerR * 0.68}
        width={innerR * 1.4}
        height={dim * 0.06}
        rx={dim * 0.01}
        fill={sc.color}
        fillOpacity="0.15"
        stroke={sc.color}
        strokeWidth={dim * 0.004}
        strokeOpacity="0.5"
      />
      <text
        x={cx}
        y={cy + innerR * 0.68 + dim * 0.043}
        textAnchor="middle"
        fontSize={fontSize.status}
        fontWeight="700"
        fontFamily="Inter, system-ui, sans-serif"
        fill={sc.color}
        letterSpacing="0.08em"
      >
        {sc.label}
      </text>

      {/* Cert ID arc text at bottom of outer ring */}
      <path
        id={`cert-arc-${cert_id.replace(/[^a-z0-9]/gi, "")}`}
        d={`M ${cx - outerR * 0.75} ${cy + outerR * 0.72} A ${outerR * 0.95} ${outerR * 0.95} 0 0 1 ${cx + outerR * 0.75} ${cy + outerR * 0.72}`}
        fill="none"
      />
      <text
        fontSize={fontSize.certId}
        fontFamily="Inter, system-ui, monospace"
        fill={tc.primaryColor}
        fillOpacity="0.6"
        letterSpacing="0.04em"
      >
        <textPath href={`#cert-arc-${cert_id.replace(/[^a-z0-9]/gi, "")}`} startOffset="50%" textAnchor="middle">
          {cert_id}
        </textPath>
      </text>

      {/* AISeal wordmark arc at top */}
      <path
        id={`aiseal-arc-${cert_id.replace(/[^a-z0-9]/gi, "")}`}
        d={`M ${cx - outerR * 0.6} ${cy - outerR * 0.78} A ${outerR * 0.9} ${outerR * 0.9} 0 0 1 ${cx + outerR * 0.6} ${cy - outerR * 0.78}`}
        fill="none"
      />
      <text
        fontSize={fontSize.certId}
        fontFamily="Inter, system-ui, sans-serif"
        fill={tc.secondaryColor}
        fillOpacity="0.7"
        letterSpacing="0.14em"
        fontWeight="600"
      >
        <textPath href={`#aiseal-arc-${cert_id.replace(/[^a-z0-9]/gi, "")}`} startOffset="50%" textAnchor="middle">
          AISEAL.AI
        </textPath>
      </text>
    </svg>
  );
}
