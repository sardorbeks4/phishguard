import type { Verdict } from "../types";

/**
 * The risk dial.
 *
 * Drawn as an SVG arc rather than an image so it scales, themes and
 * animates for free. The trick is `stroke-dasharray` + `stroke-dashoffset`:
 * you draw the full arc, then hide part of it. Animating the offset in CSS
 * makes the dial sweep up to its value.
 */

const VERDICT_TONE: Record<Verdict, string> = {
  low_risk: "var(--ok)",
  suspicious: "var(--warn)",
  likely_phishing: "var(--bad)",
  high_risk: "var(--crit)",
};

interface Props {
  score: number;
  verdict: Verdict;
  label: string;
}

export function ScoreGauge({ score, verdict, label }: Props) {
  const radius = 68;
  const circumference = Math.PI * radius; // half circle
  const filled = (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const tone = VERDICT_TONE[verdict];

  return (
    <div className="gauge" role="img" aria-label={`Risk score ${score} out of 100: ${label}`}>
      <svg viewBox="0 0 180 100" className="gauge-svg">
        {/* Track */}
        <path
          d="M 22 92 A 68 68 0 0 1 158 92"
          fill="none"
          stroke="var(--line)"
          strokeWidth="14"
          strokeLinecap="round"
        />
        {/* Value */}
        <path
          d="M 22 92 A 68 68 0 0 1 158 92"
          fill="none"
          stroke={tone}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          className="gauge-value"
        />
      </svg>
      <div className="gauge-readout">
        <span className="gauge-score" style={{ color: tone }}>
          {score}
        </span>
        <span className="gauge-max">/100</span>
      </div>
      <p className="gauge-label" style={{ color: tone }}>
        {label}
      </p>
    </div>
  );
}
