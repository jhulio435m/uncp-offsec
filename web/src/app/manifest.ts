import type { MetadataRoute } from "next";
import { DESCRIPTION } from "@/content/site";

export const dynamic = "force-static";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Soryntel Security",
    short_name: "Security",
    description: DESCRIPTION,
    lang: "es",
    start_url: "/",
    display: "browser",
    background_color: "#0b0b0c",
    theme_color: "#0b0b0c",
    icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }],
  };
}
