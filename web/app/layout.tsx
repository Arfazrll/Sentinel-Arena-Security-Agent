import "./globals.css";
import "reactflow/dist/style.css";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Sentinel Arena",
  description: "Authorized security-resilience engagements — live arena, leaderboard, audit report.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <nav className="nav">
          <span className="brand">⚔ Sentinel Arena</span>
          <Link href="/">Arena</Link>
          <Link href="/leaderboard">Leaderboard</Link>
          <span className="spacer badge">authorized · non-destructive · 127.0.0.1</span>
        </nav>
        {children}
      </body>
    </html>
  );
}
