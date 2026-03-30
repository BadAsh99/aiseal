import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Nav from "./components/Nav";
import NineChat from "./components/NineChat";

const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem('aiseal-theme');if(t){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();`;

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "AISeal — AI You Can Trust",
  description: "The first AI security trust and certification platform. Scan it. Monitor it. Certify it.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} h-full`}>
      {/* eslint-disable-next-line @next/next/no-head-element */}
      <head><script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} /></head>
      <body className="min-h-full flex flex-col" style={{ background: "var(--bg-base)", color: "var(--text-primary)" }}>
        <Nav />
        <main className="flex-1">{children}</main>
        <footer
          className="text-center py-6 text-sm"
          style={{ color: "var(--text-muted)", borderTop: "1px solid var(--border-mid)" }}
        >
          &copy; 2026 AISeal — aiseal.ai — All rights reserved
        </footer>
        <NineChat />
      </body>
    </html>
  );
}
