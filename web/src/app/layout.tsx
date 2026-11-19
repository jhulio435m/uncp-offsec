import type { Metadata, Viewport } from "next";
import "@fontsource-variable/big-shoulders";
import "@fontsource-variable/hanken-grotesk";
import "@fontsource-variable/jetbrains-mono";
import { DESCRIPTION, KEYWORDS, SITE_URL, TITLE } from "@/content/site";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: TITLE, template: "%s · Soryntel Security" },
  description: DESCRIPTION,
  applicationName: "Soryntel Security",
  keywords: KEYWORDS,
  category: "technology",
  authors: [{ name: "Soryntel", url: "https://soryntel.com" }],
  creator: "Soryntel",
  publisher: "Soryntel",
  alternates: { canonical: "/" },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-image-preview": "large", "max-snippet": -1, "max-video-preview": -1 },
  },
  formatDetection: { telephone: false, email: false, address: false },
  openGraph: {
    type: "website",
    locale: "es_PE",
    url: "/",
    siteName: "Soryntel Security",
    title: TITLE,
    description: DESCRIPTION,
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "Soryntel Security: lo encontramos antes que ellos" }],
  },
  twitter: { card: "summary_large_image", title: TITLE, description: DESCRIPTION, images: ["/og.png"] },
};

export const viewport: Viewport = { themeColor: "#0b0b0c", colorScheme: "dark" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es">
      <body>
        {/* Activa la coreografía solo si hay JavaScript: sin él, nada queda oculto. */}
        <script dangerouslySetInnerHTML={{ __html: "document.documentElement.classList.add('js')" }} />
        {children}
      </body>
    </html>
  );
}
