import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import "./styles.css";

const container = document.getElementById("root");
if (!container) throw new Error("Root element missing from index.html");

createRoot(container).render(
  // StrictMode is a development-only wrapper that double-invokes renders
  // and effects to surface bugs caused by impure components. It disappears
  // in the production build.
  <StrictMode>
    <App />
  </StrictMode>,
);
