import { useState } from "react";

import type { Finding } from "../types";

/**
 * One piece of evidence, expandable to reveal the teaching note.
 *
 * The collapsed state shows *what* was found; expanding shows *why it
 * matters*. That split is the whole pedagogy of the product: a user in a
 * hurry gets a verdict, a user who wants to learn gets the reasoning, and
 * neither one has to wade through the other.
 */

const SEVERITY_LABEL: Record<Finding["severity"], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const CATEGORY_LABEL: Record<Finding["category"], string> = {
  sender: "Sender",
  links: "Links",
  language: "Language",
  attachments: "Attachments",
  authentication: "Authentication",
};

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);

  return (
    <article className={`finding sev-${finding.severity}`}>
      <button
        type="button"
        className="finding-head"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className={`pill sev-${finding.severity}`}>
          {SEVERITY_LABEL[finding.severity]}
        </span>
        <span className="finding-title">{finding.title}</span>
        <span className="finding-cat">{CATEGORY_LABEL[finding.category]}</span>
        <span className={`chev ${open ? "open" : ""}`} aria-hidden="true">
          ▾
        </span>
      </button>

      <div className="finding-body">
        {/*
          finding.detail can quote text taken straight out of a hostile
          email. React escapes it automatically when rendered as a child —
          this is why we never touch dangerouslySetInnerHTML anywhere in
          this app. The one place an XSS could enter is the one place we
          refuse to open.
        */}
        <p className="finding-detail">{finding.detail}</p>

        {finding.evidence && (
          <pre className="evidence">
            <code>{finding.evidence}</code>
          </pre>
        )}

        {open && (
          <div className="why">
            <span className="why-tag">Why this matters</span>
            <p>{finding.why}</p>
          </div>
        )}
      </div>
    </article>
  );
}
