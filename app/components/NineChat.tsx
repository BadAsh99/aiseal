"use client";

import { useEffect, useRef, useState } from "react";

interface Message {
  role: "user" | "assistant";
  content: string;
}

const GREETING: Message = {
  role: "assistant",
  content: "NINE online. Neural Intelligence Node Engine — Ghost99RT. Ask anything about AI security, TrustScan results, or OWASP LLM Top 10.",
};

export default function NineChat() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([GREETING]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  async function sendMessage() {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: Message = { role: "user", content: text };
    const next = [...messages, userMsg];
    setMessages(next);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("/api/nine/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: next.slice(1) }), // skip greeting (not a real API turn)
      });
      const data = await res.json();
      const reply: Message = {
        role: "assistant",
        content: data.reply ?? "NINE encountered an error. Try again.",
      };
      setMessages([...next, reply]);
    } catch {
      setMessages([...next, { role: "assistant", content: "Connection lost. Ghost99RT unreachable." }]);
    } finally {
      setLoading(false);
    }
  }

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function clearChat() {
    setMessages([GREETING]);
  }

  return (
    <>
      {/* Floating button */}
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Open NINE chat"
        style={{
          position: "fixed",
          bottom: "1.5rem",
          right: "1.5rem",
          zIndex: 9999,
          width: "52px",
          height: "52px",
          borderRadius: "50%",
          background: open
            ? "rgba(168,85,247,0.9)"
            : "linear-gradient(135deg, rgba(168,85,247,0.85) 0%, rgba(109,40,217,0.9) 100%)",
          border: "1px solid rgba(168,85,247,0.5)",
          boxShadow: "0 0 20px rgba(168,85,247,0.4), 0 4px 16px rgba(0,0,0,0.5)",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          transition: "all 0.2s ease",
          color: "#fff",
          fontSize: "1.1rem",
          fontWeight: 700,
          letterSpacing: "-0.02em",
          fontFamily: "monospace",
        }}
      >
        {open ? "✕" : "N9"}
      </button>

      {/* Chat panel */}
      {open && (
        <div
          style={{
            position: "fixed",
            bottom: "5rem",
            right: "1.5rem",
            zIndex: 9998,
            width: "clamp(320px, 90vw, 420px)",
            height: "clamp(400px, 60vh, 560px)",
            background: "var(--bg-surface)",
            border: "1px solid rgba(168,85,247,0.25)",
            borderRadius: "12px",
            boxShadow: "0 0 40px rgba(168,85,247,0.12), 0 16px 48px rgba(0,0,0,0.7)",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          {/* Header */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "0.75rem 1rem",
              borderBottom: "1px solid rgba(168,85,247,0.15)",
              background: "rgba(168,85,247,0.05)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span
                style={{
                  width: "7px",
                  height: "7px",
                  borderRadius: "50%",
                  background: "#a855f7",
                  boxShadow: "0 0 6px #a855f7",
                  display: "inline-block",
                  animation: "pulse 2s infinite",
                }}
              />
              <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#a855f7", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                NINE
              </span>
              <span style={{ fontSize: "0.6rem", color: "var(--text-subtle)", letterSpacing: "0.05em" }}>
                Neural Intelligence Node Engine
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <button
                onClick={clearChat}
                title="Clear chat"
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--text-faint)",
                  fontSize: "0.65rem",
                  cursor: "pointer",
                  letterSpacing: "0.05em",
                  textTransform: "uppercase",
                  padding: "0.2rem 0.4rem",
                }}
              >
                Clear
              </button>
            </div>
          </div>

          {/* Messages */}
          <div
            style={{
              flex: 1,
              overflowY: "auto",
              padding: "1rem",
              display: "flex",
              flexDirection: "column",
              gap: "0.75rem",
              scrollbarWidth: "thin",
              scrollbarColor: "#1f2937 transparent",
            }}
          >
            {messages.map((msg, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: msg.role === "user" ? "flex-end" : "flex-start",
                }}
              >
                <div
                  style={{
                    maxWidth: "85%",
                    padding: "0.55rem 0.85rem",
                    borderRadius: msg.role === "user" ? "12px 12px 2px 12px" : "12px 12px 12px 2px",
                    background:
                      msg.role === "user"
                        ? "rgba(168,85,247,0.15)"
                        : "var(--msg-bg)",
                    border:
                      msg.role === "user"
                        ? "1px solid rgba(168,85,247,0.25)"
                        : "1px solid var(--msg-border)",
                    fontSize: "0.75rem",
                    lineHeight: "1.5",
                    color: msg.role === "user" ? "#d8b4fe" : "var(--text-primary)",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {msg.content}
                </div>
                {msg.role === "assistant" && i > 0 && (
                  <span style={{ fontSize: "0.55rem", color: "var(--text-ghost)", marginTop: "0.2rem", marginLeft: "0.25rem" }}>
                    NINE · Ghost99RT
                  </span>
                )}
              </div>
            ))}

            {loading && (
              <div style={{ display: "flex", alignItems: "flex-start" }}>
                <div
                  style={{
                    padding: "0.55rem 0.85rem",
                    borderRadius: "12px 12px 12px 2px",
                    background: "var(--msg-bg)",
                    border: "1px solid var(--msg-border)",
                    display: "flex",
                    gap: "4px",
                    alignItems: "center",
                  }}
                >
                  {[0, 1, 2].map((n) => (
                    <span
                      key={n}
                      style={{
                        width: "5px",
                        height: "5px",
                        borderRadius: "50%",
                        background: "#a855f7",
                        display: "inline-block",
                        animation: `bounce 1.2s ease-in-out ${n * 0.2}s infinite`,
                      }}
                    />
                  ))}
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div
            style={{
              padding: "0.75rem 1rem",
              borderTop: "1px solid rgba(168,85,247,0.1)",
              background: "var(--overlay-bg)",
              display: "flex",
              gap: "0.5rem",
              alignItems: "center",
            }}
          >
            <input
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Ask NINE anything..."
              disabled={loading}
              style={{
                flex: 1,
                background: "var(--msg-bg)",
                border: "1px solid rgba(168,85,247,0.2)",
                borderRadius: "8px",
                padding: "0.5rem 0.75rem",
                fontSize: "0.75rem",
                color: "var(--text-primary)",
                outline: "none",
                fontFamily: "inherit",
              }}
            />
            <button
              onClick={sendMessage}
              disabled={loading || !input.trim()}
              style={{
                background: input.trim() && !loading ? "rgba(168,85,247,0.8)" : "rgba(168,85,247,0.2)",
                border: "1px solid rgba(168,85,247,0.3)",
                borderRadius: "8px",
                padding: "0.5rem 0.85rem",
                color: input.trim() && !loading ? "#fff" : "var(--text-muted)",
                fontSize: "0.7rem",
                fontWeight: 600,
                cursor: input.trim() && !loading ? "pointer" : "not-allowed",
                transition: "all 0.15s ease",
                letterSpacing: "0.05em",
                textTransform: "uppercase",
              }}
            >
              Send
            </button>
          </div>
        </div>
      )}

      <style>{`
        @keyframes bounce {
          0%, 80%, 100% { transform: scale(0.6); opacity: 0.4; }
          40% { transform: scale(1); opacity: 1; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </>
  );
}
