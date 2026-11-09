import "./globals.css";
import "reactflow/dist/style.css";
import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Shell from "@/components/Shell";

const sans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-sans",
  display: "swap",
});
const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "Sentinel Arena", template: "%s · Sentinel Arena" },
  description:
    "Authorized red-vs-blue agent engagements against your own sandbox: live arena, replay, resilience scoring, compliance-mapped findings.",
};

// Set the theme before paint so there is no flash of the wrong theme.
// With no saved choice, follow the OS setting.
const themeScript = `(function(){var d=document.documentElement,t=null;try{t=localStorage.getItem("sa-theme")}catch(e){}if(t!=="light"&&t!=="dark"){t=window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}d.dataset.theme=t})()`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
