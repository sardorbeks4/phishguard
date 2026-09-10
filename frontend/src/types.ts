/**
 * The API contract, mirrored in TypeScript.
 *
 * These types are hand-written to match backend/app/schemas.py. Keeping
 * them in sync by hand is fine at this size; the moment it stops being
 * fine, generate them from the OpenAPI schema FastAPI already publishes
 * at /openapi.json (`npx openapi-typescript`). Worth knowing that option
 * exists before you write the 200th interface by hand.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Category =
  | "sender"
  | "links"
  | "language"
  | "attachments"
  | "authentication";
export type Verdict = "low_risk" | "suspicious" | "likely_phishing" | "high_risk";

export interface Finding {
  code: string;
  category: Category;
  severity: Severity;
  title: string;
  detail: string;
  why: string;
  evidence: string | null;
  meta: Record<string, unknown>;
}

export interface AnalyzeResponse {
  score: number;
  verdict: Verdict;
  verdict_label: string;
  summary: string;
  findings: Finding[];
  by_category: Record<Category, Finding[]>;
  advice: string[];
  parsed: {
    from_display: string;
    from_address: string;
    reply_to: string;
    subject: string;
    attachments: string[];
    link_count: number;
    input_mode: string;
  };
  meta: {
    duration_ms: number;
    detector_errors: string[];
    engine_version: string;
  };
}

export interface Sample {
  id: string;
  name: string;
  difficulty: "easy" | "medium" | "hard";
  is_phishing: boolean;
  teaching_point: string;
  sender: string;
  subject: string;
  body: string;
  attachments: string[];
}

export interface AnalyzeRequest {
  sender?: string;
  subject?: string;
  body?: string;
  reply_to?: string;
  attachments?: string[];
  raw?: string;
}
