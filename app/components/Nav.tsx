"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export default function Nav() {
  const pathname = usePathname();

  const links = [
    { href: "/scan", label: "TrustScan" },
    { href: "/registry", label: "Registry" },
    { href: "/monitor", label: "Monitor" },
  ];

  return (
    <nav
      className="flex items-center justify-between px-8 py-4"
      style={{
        background: "#111111",
        borderBottom: "1px solid #2a2a2a",
        position: "sticky",
        top: 0,
        zIndex: 50,
      }}
    >
      <Link href="/" className="flex items-center gap-2 no-underline">
        <ShieldIcon />
        <span
          className="font-bold text-xl tracking-tight"
          style={{ color: "#ededed", letterSpacing: "-0.02em" }}
        >
          AI<span style={{ color: "#0080ff" }}>Seal</span>
        </span>
      </Link>

      <div className="flex items-center gap-6">
        {links.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="text-sm font-medium transition-colors"
              style={{
                color: pathname === link.href ? "#0080ff" : "#6b7280",
                textDecoration: "none",
              }}
            >
              {link.label}
            </Link>
          ))}
        {pathname !== "/scan" && pathname !== "/monitor" && (
          <a
            href="/scan"
            className="text-sm font-medium px-4 py-2 rounded-md transition-colors"
            style={{
              background: "#0080ff",
              color: "#ffffff",
              textDecoration: "none",
            }}
          >
            Run Scan
          </a>
        )}
      </div>
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
