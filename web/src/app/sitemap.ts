import type { MetadataRoute } from "next";
import { SITE_URL } from "@/content/site";

export const dynamic = "force-static";

const PAGES = ["", "auditoria", "reglas", "informe", "plataforma", "preguntas", "solicitar"];

export default function sitemap(): MetadataRoute.Sitemap {
  return PAGES.map((p) => ({ url: `${SITE_URL}/${p}`, changeFrequency: "monthly", priority: p ? 0.8 : 1 }));
}
