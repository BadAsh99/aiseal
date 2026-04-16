"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import ThemeToggle from "./ThemeToggle";

export default function Nav() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const links = [
    { href: "/scan", label: "TrustScan" },
    { href: "/scan/quantum", label: "QR Scan" },
    { href: "/registry", label: "Registry" },
    { href: "/monitor", label: "Monitor" },
    { href: "/registry/apply", label: "Apply" },
  ];

  return (
    <nav
      className="flex items-center justify-between px-4 sm:px-8 py-4 relative"
      style={{
        background: "var(--bg-surface)",
        borderBottom: "1px solid var(--border-mid)",
        position: "sticky",
        top: 0,
        zIndex: 50,
      }}
    >
      <Link href="/" className="flex items-center gap-2 no-underline">
        <ShieldIcon />
        <span
          className="font-bold text-xl tracking-tight"
          style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }}
        >
          AI<span style={{ color: "#0080ff" }}>Seal</span>
        </span>
      </Link>

      {/* Desktop nav */}
      <div className="hidden sm:flex items-center gap-4">
        <div className="flex items-center gap-6">
          {links.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="text-sm font-medium transition-colors"
                style={{
                  color: pathname === link.href ? "#0080ff" : "var(--text-muted)",
                  textDecoration: "none",
                }}
              >
                {link.label}
              </Link>
            ))}
          {pathname !== "/registry/apply" && (
            <a
              href="/registry/apply"
              className="text-sm font-medium px-4 py-2 rounded-md transition-colors"
              style={{
                background: "#00c853",
                color: "#000000",
                textDecoration: "none",
              }}
            >
              Get Certified
            </a>
          )}
        </div>
        <ThemeToggle />
      </div>

      {/* Mobile hamburger */}
      <div className="flex sm:hidden items-center gap-3">
        <ThemeToggle />
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
          className="p-1"
          style={{ color: "var(--text-muted)" }}
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            {mobileOpen
              ? <><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></>
              : <><line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" /></>}
          </svg>
        </button>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div
          className="absolute top-full left-0 right-0 flex flex-col gap-1 p-4 sm:hidden"
          style={{ background: "var(--bg-surface)", borderBottom: "1px solid var(--border-mid)" }}
        >
          {links.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setMobileOpen(false)}
              className="text-sm font-medium py-2 px-3 rounded-md transition-colors"
              style={{
                color: pathname === link.href ? "#0080ff" : "var(--text-muted)",
                textDecoration: "none",
                background: pathname === link.href ? "rgba(0,128,255,0.08)" : "transparent",
              }}
            >
              {link.label}
            </Link>
          ))}
          {pathname !== "/registry/apply" && (
            <a
              href="/registry/apply"
              onClick={() => setMobileOpen(false)}
              className="text-sm font-semibold py-2 px-3 rounded-md mt-1 text-center"
              style={{ background: "#00c853", color: "#000000", textDecoration: "none" }}
            >
              Get Certified
            </a>
          )}
        </div>
      )}
    </nav>
  );
}

function ShieldIcon() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M12 2L4 6V12C4 16.4 7.4 20.5 12 22C16.6 20.5 20 16.4 20 12V6L12 2Z"
        fill="#0080ff"
        fillOpacity="0.15"
        stroke="#0080ff"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9 12L11 14L15 10"
        stroke="#0080ff"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
