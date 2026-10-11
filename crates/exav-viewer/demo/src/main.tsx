import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "@exav/viewer/styles.css";
import "./demo.css";
import { App } from "./App.js";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
