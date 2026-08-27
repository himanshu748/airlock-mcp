import type { NextConfig } from "next";

// Static export so the FastAPI backend serves the interface at /ui/ from the
// same process. One process for the demo, no CORS, no second port.
const nextConfig: NextConfig = {
  output: "export",
  basePath: "/ui",
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
};

export default nextConfig;
