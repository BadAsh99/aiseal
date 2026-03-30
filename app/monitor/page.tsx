export default function MonitorPage() {
  return (
    <div
      style={{
        background: "#0a0a0a",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Ghost99OC watermark */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          pointerEvents: "none",
          userSelect: "none",
          paddingLeft: "4rem",
        }}
      >
        <span
          style={{
            fontSize: "clamp(5rem, 18vw, 16rem)",
            fontWeight: 900,
            letterSpacing: "-0.04em",
            lineHeight: 1,
            color: "transparent",
            WebkitTextStroke: "1px rgba(255,255,255,0.06)",
            background: "linear-gradient(180deg, rgba(255,255,255,0.07) 0%, rgba(255,255,255,0.01) 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            whiteSpace: "nowrap",
          }}
        >
          Ghost99OC
        </span>
      </div>

      {/* Subtle radial glow behind text */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: "radial-gradient(ellipse 60% 40% at 50% 50%, rgba(168,85,247,0.04) 0%, transparent 70%)",
          pointerEvents: "none",
        }}
      />

      {/* Content */}
      <div
        style={{
          position: "relative",
          zIndex: 10,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "1.5rem",
          textAlign: "center",
          padding: "0 1.5rem",
        }}
      >
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.5rem",
            padding: "0.25rem 0.75rem",
            borderRadius: "9999px",
            background: "rgba(168,85,247,0.08)",
            border: "1px solid rgba(168,85,247,0.2)",
          }}
        >
          <span
            style={{
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              background: "#a855f7",
              display: "inline-block",
              boxShadow: "0 0 6px #a855f7",
            }}
          />
          <span style={{ fontSize: "0.7rem", fontWeight: 600, color: "#a855f7", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            AISeal Monitor
          </span>
        </div>

        <div>
          <p
            style={{
              fontSize: "1.5rem",
              fontWeight: 700,
              color: "rgba(237,237,237,0.9)",
              letterSpacing: "-0.02em",
              marginBottom: "0.5rem",
            }}
          >
            Coming Soon
          </p>
          <p style={{ fontSize: "0.95rem", color: "rgba(107,114,128,0.8)", maxWidth: "380px", lineHeight: 1.6 }}>
            Runtime LLM behavioral surveillance. Every prompt. Every response. Every anomaly — caught before it becomes an incident.
          </p>
        </div>

        <p
          style={{
            fontSize: "0.75rem",
            color: "rgba(107,114,128,0.4)",
            letterSpacing: "0.05em",
          }}
        >
          Powered by Ghost99OC
        </p>
      </div>
    </div>
  );
}
