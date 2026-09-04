import React from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/geist";
import "bootstrap-icons/font/bootstrap-icons.min.css";
import { App } from "./App.jsx";
import "./dark-matte.css";

const themeQuery = new URLSearchParams(window.location.search).get("theme");
const themeOverride = themeQuery === "light" || themeQuery === "dark" ? themeQuery : null;
const colorScheme = window.matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => {
  const theme = themeOverride || (colorScheme.matches ? "dark" : "light");
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0b1118" : "#f3f5f2");
};
applyTheme();
if (!themeOverride) colorScheme.addEventListener("change", applyTheme);

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
