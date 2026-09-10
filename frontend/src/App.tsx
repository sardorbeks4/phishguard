import { useEffect, useState } from "react";

import { api, ApiError } from "./api";
import { FindingCard } from "./components/FindingCard";
import { ScoreGauge } from "./components/ScoreGauge";
import type { AnalyzeResponse, Sample } from "./types";

/**
 * The whole app in one component, on purpose.
 *
 * At this size, splitting state across five components and a store costs
 * more than it saves. The rule of thumb: extract a component when it has
 * its own state or gets reused, not because a file is getting long. When
 * this grows past a few more features, the analysis form and the results
 * panel are the natural seams.
 */

type Mode = "fields" | "raw";

export default function App() {
  const [mode, setMode] = useState<Mode>("fields");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [attachments, setAttachments] = useState("");
  const [raw, setRaw] = useState("");

  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [samples, setSamples] = useState<Sample[]>([]);
  const [activeSample, setActiveSample] = useState<Sample | null>(null);
  const [revealed, setRevealed] = useState(false);

  // Load the training corpus once on mount. The empty dependency array is
  // what makes it "once" — leave it off and this refetches on every render.
  useEffect(() => {
    api.samples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function runAnalysis() {
    setLoading(true);
    setError(null);
    try {
      const payload =
        mode === "raw"
          ? { raw }
          : {
              sender,
              subject,
              body,
              attachments: attachments
                .split(/[,\n]/)
                .map((s) => s.trim())
                .filter(Boolean),
            };
      setResult(await api.analyze(payload));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
      setResult(null);
    } finally {
      // `finally` matters: without it, an error path leaves the spinner
      // running forever.
      setLoading(false);
    }
  }

  function loadSample(sample: Sample) {
    setMode("fields");
    setActiveSample(sample);
    setRevealed(false);
    setSender(sample.sender);
    setSubject(sample.subject);
    setBody(sample.body);
    setAttachments(sample.attachments.join(", "));
    setResult(null);
    setError(null);
  }

  function clearAll() {
    setSender("");
    setSubject("");
    setBody("");
    setAttachments("");
    setRaw("");
    setResult(null);
    setError(null);
    setActiveSample(null);
    setRevealed(false);
  }

  const canSubmit =
    !loading && (mode === "raw" ? raw.trim().length > 0 : (body + sender + subject).trim().length > 0);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">◆</span>
          <div>
            <h1>PhishGuard</h1>
            <p>Paste a suspicious email. Find out what's wrong with it, and why.</p>
          </div>
        </div>
        <span className="privacy-note">
          Analysis runs on the server and nothing is stored. No links are ever fetched.
        </span>
      </header>

      <main className="layout">
        {/* ------------------------------ INPUT ------------------------------ */}
        <section className="panel">
          <div className="panel-head">
            <h2>The email</h2>
            <div className="modes">
              <button
                className={mode === "fields" ? "active" : ""}
                onClick={() => setMode("fields")}
              >
                Fields
              </button>
              <button className={mode === "raw" ? "active" : ""} onClick={() => setMode("raw")}>
                Full source
              </button>
            </div>
          </div>

          {mode === "fields" ? (
            <div className="form">
              <label>
                From
                <input
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  placeholder="Support Team &lt;billing@example-verify.info&gt;"
                  spellCheck={false}
                />
              </label>
              <label>
                Subject
                <input
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="Urgent: action required on your account"
                />
              </label>
              <label>
                Body
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  rows={12}
                  placeholder="Paste the message text or HTML here…"
                  spellCheck={false}
                />
              </label>
              <label>
                Attachment names <span className="hint">comma separated</span>
                <input
                  value={attachments}
                  onChange={(e) => setAttachments(e.target.value)}
                  placeholder="invoice.pdf.exe, statement.xlsm"
                  spellCheck={false}
                />
              </label>
            </div>
          ) : (
            <div className="form">
              <p className="hint block">
                In Gmail open the message → ⋮ → <strong>Show original</strong>, then paste
                everything here. Full headers unlock the SPF, DKIM and DMARC checks.
              </p>
              <textarea
                value={raw}
                onChange={(e) => setRaw(e.target.value)}
                rows={20}
                placeholder="Received: from …&#10;Authentication-Results: …&#10;From: …"
                spellCheck={false}
              />
            </div>
          )}

          <div className="actions">
            <button className="primary" onClick={runAnalysis} disabled={!canSubmit}>
              {loading ? "Analyzing…" : "Analyze"}
            </button>
            <button className="ghost" onClick={clearAll}>
              Clear
            </button>
          </div>

          <div className="samples">
            <h3>Training samples</h3>
            <p className="hint block">
              Every sample is fictional. Decide for yourself first, then check.
            </p>
            <div className="sample-list">
              {samples.map((s) => (
                <button
                  key={s.id}
                  className={`sample ${activeSample?.id === s.id ? "active" : ""}`}
                  onClick={() => loadSample(s)}
                >
                  <span className="sample-name">{s.name}</span>
                  <span className={`diff ${s.difficulty}`}>{s.difficulty}</span>
                </button>
              ))}
            </div>

            {activeSample && (
              <div className="answer">
                {revealed ? (
                  <>
                    <p className={activeSample.is_phishing ? "bad-text" : "ok-text"}>
                      {activeSample.is_phishing ? "This one is phishing." : "This one is legitimate."}
                    </p>
                    <p className="teaching">{activeSample.teaching_point}</p>
                  </>
                ) : (
                  <button className="ghost" onClick={() => setRevealed(true)}>
                    Reveal the answer
                  </button>
                )}
              </div>
            )}
          </div>
        </section>

        {/* ----------------------------- RESULTS ----------------------------- */}
        <section className="panel results">
          {error && <div className="error">{error}</div>}

          {!result && !error && (
            <div className="empty">
              <p>No analysis yet.</p>
              <p className="hint">
                Paste an email or pick a training sample, then hit Analyze.
              </p>
            </div>
          )}

          {result && (
            <>
              <div className="verdict-row">
                <ScoreGauge
                  score={result.score}
                  verdict={result.verdict}
                  label={result.verdict_label}
                />
                <div className="verdict-text">
                  <p className="summary">{result.summary}</p>
                  <dl className="parsed">
                    {result.parsed.from_address && (
                      <>
                        <dt>Actual sender</dt>
                        <dd>{result.parsed.from_address}</dd>
                      </>
                    )}
                    {result.parsed.reply_to && (
                      <>
                        <dt>Replies go to</dt>
                        <dd>{result.parsed.reply_to}</dd>
                      </>
                    )}
                    <dt>Links found</dt>
                    <dd>{result.parsed.link_count}</dd>
                    <dt>Attachments</dt>
                    <dd>{result.parsed.attachments.length || "none"}</dd>
                  </dl>
                </div>
              </div>

              <div className="advice">
                <h3>What to do</h3>
                <ul>
                  {result.advice.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </div>

              <div className="findings">
                <h3>
                  Indicators <span className="count">{result.findings.length}</span>
                </h3>
                {result.findings.length === 0 ? (
                  <p className="hint block">
                    No indicators matched. That is not proof of safety — a careful,
                    targeted email can pass every automated check.
                  </p>
                ) : (
                  result.findings.map((f) => <FindingCard key={f.code + f.evidence} finding={f} />)
                )}
              </div>

              <p className="meta">
                Engine {result.meta.engine_version} · {result.meta.duration_ms} ms
              </p>
            </>
          )}
        </section>
      </main>
    </div>
  );
}
