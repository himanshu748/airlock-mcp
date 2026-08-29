import type { NextConfig } from "next";

// Static export so the FastAPI backend serves the interface at /ui/ from the
// same process. One process for the demo, no CORS, no second port.
//
// The hosted build is the same export served at a root instead, so the base
// path is the one thing that differs between them. AIRLOCK_UI_BASE_PATH=""
// produces the hosted variant.
const basePath = process.env.AIRLOCK_UI_BASE_PATH ?? "/ui";

const nextConfig: NextConfig = {
  output: "export",
  ...(basePath ? { basePath } : {}),
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default nextConfig;
