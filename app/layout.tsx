import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Nav from "./components/Nav";
import NineChat from "./components/NineChat";

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
      <body className="min-h-full flex flex-col" style={{ background: "#0a0a0a", color: "#ededed" }}>
        <Nav />
        <main className="flex-1">{children}</main>
        <footer
          className="text-center py-6 text-sm"
          style={{ color: "#6b7280", borderTop: "1px solid #2a2a2a" }}
        >
          &copy; 2026 AISeal — aiseal.ai — All rights reserved
        </footer>
        <NineChat />
      </body>
    </html>
  );
}
