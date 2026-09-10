/**
 * The single place the frontend talks to the network.
 *
 * Why centralise it: every fetch needs the same error handling, the same
 * timeout and the same base URL. Scattering `fetch` through components is
 * how you end up with five different ways of showing "something broke".
 */

import type { AnalyzeRequest, AnalyzeResponse, Sample } from "./types";

const TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // AbortController is how you cancel a fetch. Without a timeout a hung
  // backend leaves the UI spinning forever with no way out.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(path, {
      ...init,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });

    if (response.status === 429) {
      throw new ApiError(
        "Too many requests. Wait a moment and try again.",
        429,
      );
    }
    if (!response.ok) {
      // FastAPI puts validation problems in `detail`, which may be a string
      // or an array of per-field errors.
      let detail = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        if (typeof body.detail === "string") detail = body.detail;
        else if (Array.isArray(body.detail) && body.detail[0]?.msg)
          detail = body.detail[0].msg;
      } catch {
        /* body wasn't JSON; keep the generic message */
      }
      throw new ApiError(detail, response.status);
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("The analysis timed out. Is the backend running?");
    }
    throw new ApiError(
      "Couldn't reach the analysis service. Is the backend running on port 8000?",
    );
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  analyze: (payload: AnalyzeRequest) =>
    request<AnalyzeResponse>("/api/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  samples: () => request<Sample[]>("/api/samples"),
};
