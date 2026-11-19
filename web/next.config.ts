import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Sitio estático: `next build` deja la página desplegable en out/.
  output: "export",
  poweredByHeader: false,
  reactStrictMode: true,
  images: { unoptimized: true },
  // El repositorio tiene otro package-lock en la raíz; la web es su propia raíz.
  turbopack: { root: process.cwd() },
};

export default nextConfig;
