# AISEAL TRUST OS — FULL PLATFORM ARCHITECTURE
### Version 1.0 | Classification: Internal Engineering Reference
### Author: Architecture Design Session — April 2026

---

## EXECUTIVE FRAME

What SSL/TLS did for the web in 1995, AISeal does for AI in 2026.

SSL solved a trust bootstrapping problem: how does a browser know the server it's talking to is legitimate and hasn't been tampered with? The answer was a Certificate Authority hierarchy, signed certificates, and a real-time revocation protocol (OCSP). Every HTTPS connection in the world invokes that infrastructure in under 50ms.

AISeal solves the same problem for AI: how does an enterprise know the AI system it just purchased, integrated, and connected to sensitive data is actually what the vendor claims — and hasn't degraded, been compromised, or started behaving badly since purchase?

The answer is the same architecture pattern, adapted for AI:

```
SSL/TLS                     AISeal
──────────────────────────────────────────────────────
Certificate Authority  →    AISeal CA (cert signing)
X.509 Certificate      →    AISeal TrustCert
OCSP                   →    AISeal VRS (Verify/Revoke Service)
CRL                    →    AISeal CRL + Revocation Engine
SSL Labs scan          →    AISeal Scan (OWASP LLM Top 10)
Browser padlock        →    AISeal Badge (embedded JS widget)
Public CT logs         →    AISeal Public Registry
```

This document specifies the full platform architecture to build that infrastructure.

---

## SYSTEM OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AISEAL TRUST OS                                   │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  AISeal Scan │  │  AISeal Cert │  │AISeal Monitor│  │AISeal Registry│  │
│  │  (scanner)   │  │  (CA + cert  │  │  (SDK/ghost  │  │  (source of   │  │
│  │              │  │   pipeline)  │  │   99rt SDK)  │  │    truth)     │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
│         │                 │                  │                  │           │
│  ┌──────▼─────────────────▼──────────────────▼──────────────────▼───────┐  │
│  │                      AISEAL CORE PLATFORM                            │  │
│  │                                                                      │  │
│  │   ┌────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │  │
│  │   │  Scan Job  │  │   AISeal    │  │  VRS (OCSP   │  │  Audit   │  │  │
│  │   │   Queue    │  │   CA Core   │  │  equivalent) │  │   Log    │  │  │
│  │   └────────────┘  └─────────────┘  └──────────────┘  └──────────┘  │  │
│  │                                                                      │  │
│  │   ┌────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │  │
│  │   │  Registry  │  │  Revocation │  │   Webhook    │  │  Public  │  │  │
│  │   │    DB      │  │   Engine    │  │   Dispatch   │  │   API    │  │  │
│  │   └────────────┘  └─────────────┘  └──────────────┘  └──────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                      INFRASTRUCTURE LAYER                            │  │
│  │   PostgreSQL (registry)  │  Redis (cert status cache)                │  │
│  │   S3/GCS (scan artifacts)│  CloudHSM (CA private key)                │  │
│  │   BullMQ (job queue)     │  Prometheus + Grafana (observability)     │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## PART 1: DATA MODELS

### 1.1 Registry — Core Tables

```sql
-- VENDORS: The entity that owns the AI product
CREATE TABLE vendors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT UNIQUE NOT NULL,          -- "meridian-health"
    display_name    TEXT NOT NULL,                 -- "Meridian Health Systems"
    domain          TEXT,                          -- "meridianhealth.com"
    contact_email   TEXT NOT NULL,
    verified_domain BOOLEAN DEFAULT FALSE,         -- domain ownership verified
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- AI_PRODUCTS: The specific AI system being certified
CREATE TABLE ai_products (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id       UUID REFERENCES vendors(id) ON DELETE CASCADE,
    slug            TEXT UNIQUE NOT NULL,          -- "meridian-health/clinical-assist-v3"
    display_name    TEXT NOT NULL,                 -- "ClinicalAssist v3"
    version         TEXT NOT NULL,                 -- "3.2.1"
    category        TEXT NOT NULL,                 -- "Healthcare AI"
    description     TEXT,
    base_model      TEXT,                          -- "claude-sonnet-4-6", "gpt-4o"
    architecture    TEXT[],                        -- ["RAG", "agentic", "fine-tuned"]
    handles_pii     BOOLEAN DEFAULT FALSE,
    handles_phi     BOOLEAN DEFAULT FALSE,
    handles_financial BOOLEAN DEFAULT FALSE,
    generates_code  BOOLEAN DEFAULT FALSE,
    is_agentic      BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- CERTS: The issued certificate
CREATE TABLE certs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id         TEXT UNIQUE NOT NULL,          -- "AC-2026-001" (human-readable)
    serial          BIGSERIAL,                     -- monotonic serial for CRL
    product_id      UUID REFERENCES ai_products(id) ON DELETE RESTRICT,
    scan_id         UUID REFERENCES scans(id),     -- the scan that earned this cert
    tier            TEXT NOT NULL CHECK (tier IN ('certified', 'certified-plus', 'enterprise')),
    trust_score     INTEGER NOT NULL CHECK (trust_score BETWEEN 0 AND 100),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'expiring', 'expired', 'revoked', 'suspended')),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,          -- issued_at + 1 year
    revoked_at      TIMESTAMPTZ,
    revocation_reason TEXT,
    signature       TEXT NOT NULL,                 -- base64(ECDSA-P256 signature over cert_payload)
    cert_payload    JSONB NOT NULL,                -- the signed data blob
    public          BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- SCANS: Every scan run, including pre-cert scans
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id      UUID REFERENCES ai_products(id),
    vendor_id       UUID REFERENCES vendors(id),
    scan_type       TEXT NOT NULL CHECK (scan_type IN ('pre-cert', 'certification', 'renewal', 'audit', 'api')),
    status          TEXT NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'failed')),
    trust_score     INTEGER,
    findings        JSONB,                         -- array of Finding objects
    model_tested    TEXT,
    scenario        TEXT,
    prompt_count    INTEGER DEFAULT 0,
    triggered_by    TEXT,                          -- 'api', 'scheduled', 'renewal', 'manual'
    api_key_id      UUID REFERENCES api_keys(id),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    latency_ms      INTEGER,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- MONITOR_EVENTS: Telemetry from embedded SDK
CREATE TABLE monitor_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id      UUID REFERENCES ai_products(id),
    cert_id         UUID REFERENCES certs(id),
    event_type      TEXT NOT NULL,                 -- 'threat_blocked', 'threat_warn', 'anomaly', 'health'
    severity        TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    owasp_category  TEXT,                          -- 'LLM01', 'LLM06', etc
    prompt_hash     TEXT,                          -- SHA-256 of prompt, never raw prompt
    response_hash   TEXT,                          -- SHA-256 of response
    latency_ms      INTEGER,
    sdk_version     TEXT,
    region          TEXT,
    metadata        JSONB,                         -- non-PII context
    ts              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- API_KEYS
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id       UUID REFERENCES vendors(id),
    key_hash        TEXT UNIQUE NOT NULL,          -- SHA-256 of key, never plaintext
    key_prefix      TEXT NOT NULL,                 -- "ask_live_xxxx" (first 12 chars)
    label           TEXT,
    scopes          TEXT[] NOT NULL DEFAULT '{"scan:read"}',
    rate_limit_rpm  INTEGER DEFAULT 60,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- REVOCATION_LOG: Immutable append-only
CREATE TABLE revocation_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id         UUID REFERENCES certs(id),
    action          TEXT NOT NULL CHECK (action IN ('revoke', 'suspend', 'reinstate', 'expire')),
    reason          TEXT NOT NULL,
    triggered_by    TEXT NOT NULL,                 -- 'aiseal_admin', 'automated_monitor', 'vendor_request'
    operator_id     TEXT,                          -- internal operator identity
    evidence        JSONB,                         -- scan_ids, monitor_event_ids, external refs
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- AUDIT_LOG: Everything that touches cert status — tamper-evident
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type     TEXT NOT NULL,                 -- 'cert', 'vendor', 'api_key', 'scan'
    entity_id       UUID NOT NULL,
    action          TEXT NOT NULL,
    actor           TEXT NOT NULL,                 -- operator identity or 'system'
    actor_ip        INET,
    before_state    JSONB,
    after_state     JSONB,
    request_id      TEXT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- WEBHOOKS: Subscriber notification config
CREATE TABLE webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id       UUID REFERENCES vendors(id),
    url             TEXT NOT NULL,
    secret          TEXT NOT NULL,                 -- HMAC signing secret (stored encrypted)
    events          TEXT[] NOT NULL,               -- ['cert.revoked', 'cert.expiring', 'cert.issued']
    active          BOOLEAN DEFAULT TRUE,
    last_delivery_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Indexes for hot paths
CREATE INDEX idx_certs_product_id ON certs(product_id);
CREATE INDEX idx_certs_status ON certs(status);
CREATE INDEX idx_certs_serial ON certs(serial);
CREATE INDEX idx_scans_product_id ON scans(product_id);
CREATE INDEX idx_monitor_events_product_id ON monitor_events(product_id);
CREATE INDEX idx_monitor_events_ts ON monitor_events(ts DESC);
CREATE INDEX idx_revocation_log_cert_id ON revocation_log(cert_id);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
```

---

## PART 2: AISEAL CA — CERTIFICATION AUTHORITY

### 2.1 Key Hierarchy

```
AISeal Root CA (OFFLINE — HSM)
└── AISeal Intermediate CA (ONLINE — HSM, rotated annually)
    └── AISeal TrustCert (per-product, 1-year validity)
```

The Root CA private key NEVER touches a networked system. It lives in an air-gapped HSM (AWS CloudHSM or dedicated Thales Luna). The Intermediate CA does the actual signing and runs on the network. This mirrors the WebPKI model exactly.

### 2.2 TrustCert Payload (what gets signed)

```json
{
  "version": "1",
  "cert_id": "AC-2026-001",
  "serial": 1001,
  "subject": {
    "vendor_id": "uuid-...",
    "vendor_name": "Meridian Health Systems",
    "product_id": "uuid-...",
    "product_name": "ClinicalAssist v3",
    "product_version": "3.2.1"
  },
  "certification": {
    "tier": "enterprise",
    "trust_score": 91,
    "scan_id": "uuid-...",
    "assessed_controls": ["LLM01", "LLM02", "LLM04", "LLM05", "LLM06", "LLM07"],
    "mandatory_controls_passed": ["LLM01", "LLM06", "LLM07"],
    "conditional_controls_passed": ["LLM02", "LLM04", "LLM05"],
    "compliance_mappings": {
      "owasp": "LLM Top 10 v1.1",
      "nist": "AI RMF 1.0",
      "mitre": "ATLAS v14"
    }
  },
  "validity": {
    "issued_at": "2026-02-01T00:00:00Z",
    "expires_at": "2027-02-01T00:00:00Z",
    "renewable": true
  },
  "issuer": {
    "name": "AISeal Intermediate CA v1",
    "url": "https://ca.aiseal.ai"
  }
}
```

**Signing:** ECDSA-P256. The payload is canonical JSON (sorted keys, no whitespace), SHA-256 hashed, then signed by the Intermediate CA key via HSM. The signature is stored in `certs.signature`. Verification requires only the AISeal public CA cert (distributable freely).

### 2.3 Forgery Prevention

Three layers:

1. **Cryptographic:** The signature is ECDSA-P256 over the canonical payload. Forging requires the Intermediate CA private key, which never leaves the HSM.

2. **Registry cross-check:** The `cert_id` and `serial` are authoritative in the PostgreSQL registry. Any badge claiming "AC-2026-001" can be verified against `GET /v1/cert/AC-2026-001/verify`. The verify endpoint compares the presented signature against the stored payload.

3. **Real-time status check:** Verification always hits the VRS (see Part 3). A stolen cert that gets revoked is invalid within 60 seconds.

---

## PART 3: VRS — VERIFY/REVOKE SERVICE (OCSP EQUIVALENT)

### 3.1 Architecture

The VRS is the hot path. Every badge embed, every enterprise verification, every procurement tool integration calls this. It must be fast and highly available.

```
Client → CDN Edge Cache (60s TTL) → VRS API → Redis cert status cache (60s TTL)
                                              → PostgreSQL (on cache miss)
```

Target SLA: p50 < 15ms, p99 < 50ms, 99.99% uptime.

### 3.2 VRS API

```
GET /v1/cert/{cert_id}/verify

Response 200 — GOOD:
{
  "cert_id": "AC-2026-001",
  "status": "good",
  "tier": "enterprise",
  "trust_score": 91,
  "product": "ClinicalAssist v3",
  "vendor": "Meridian Health Systems",
  "issued_at": "2026-02-01T00:00:00Z",
  "expires_at": "2027-02-01T00:00:00Z",
  "next_update": "2026-04-11T12:01:00Z",  -- when to check again (60s from now)
  "signature_valid": true
}

Response 200 — REVOKED:
{
  "cert_id": "AC-2026-001",
  "status": "revoked",
  "revoked_at": "2026-04-10T14:22:00Z",
  "revocation_reason": "Runtime monitoring detected sustained LLM01 violations",
  "next_update": "2026-04-11T12:01:00Z"
}

Response 200 — EXPIRED:
{
  "cert_id": "AC-2026-001",
  "status": "expired",
  "expired_at": "2026-02-01T00:00:00Z"
}

Response 404:
{
  "status": "unknown",
  "detail": "Cert ID not found in AISeal Registry"
}
```

No auth required on verify. This is intentionally public — same as OCSP. The response is cached aggressively (60s at Redis, 60s at CDN edge). Revocation propagates to every edge within 60 seconds.

### 3.3 Cache Strategy

```
Redis key:  cert_status:{cert_id}
Value:      serialized JSON of verify response
TTL:        60 seconds
Invalidation: on any cert status change, delete the key immediately
              → next request repopulates from PostgreSQL
              → CDN has its own 60s TTL (eventual consistency, max 120s revocation lag)
```

**Revocation lag SLA:** Max 120 seconds from revocation action to global propagation (Redis TTL 60s + CDN TTL 60s). This is documented and acceptable. SSL OCSP has the same lag for cached responses. For immediate revocation (emergency), CDN cache can be purged via API.

---

## PART 4: AISEAL CRL — CERTIFICATE REVOCATION LIST

### 4.1 CRL Format

```json
{
  "version": "1",
  "issuer": "AISeal Intermediate CA v1",
  "this_update": "2026-04-11T12:00:00Z",
  "next_update": "2026-04-11T13:00:00Z",
  "revoked": [
    {
      "cert_id": "AC-2025-019",
      "serial": 1019,
      "revoked_at": "2026-04-10T14:22:00Z",
      "reason": "keyCompromise"
    }
  ],
  "signature": "base64(ECDSA-P256 over canonical payload)"
}
```

Published at `https://crl.aiseal.ai/current.json` and `https://crl.aiseal.ai/current.crl` (DER encoded). Updated hourly and on every revocation event. Signed by Intermediate CA.

### 4.2 Revocation Triggers

Four paths to revocation:

```
1. MANUAL (AISeal admin)
   POST /v1/admin/cert/revoke
   → requires: admin JWT + reason + evidence (scan_ids or monitor_event_ids)
   → writes revocation_log → updates certs.status → invalidates Redis cache
   → publishes webhook event 'cert.revoked'
   → rebuilds CRL

2. AUTOMATED (Monitor threshold breach)
   AISeal Monitor SDK sends events to POST /v1/monitor/events
   Monitor Anomaly Engine evaluates:
     - If cert is Enterprise tier AND
     - 3+ critical events in rolling 24h window OR
     - sustained LLM01/LLM06 breach pattern
   → triggers auto-suspension (not full revocation)
   → notifies AISeal admin for manual review → admin confirms revocation

3. SCHEDULED (Expiry)
   Daily job scans certs.expires_at < now()
   → updates status to 'expired'
   → fires 'cert.expired' webhook

4. VENDOR REQUEST
   POST /v1/cert/{cert_id}/request-revoke  (authenticated, vendor API key)
   → vendor can revoke their own cert (product sunset, major version change)
   → queued for admin confirmation before taking effect
```

---

## PART 5: PUBLIC REST API

### 5.1 Authentication

Two-tier auth:

```
Public (no auth):
  GET /v1/registry/*       — read-only registry queries
  GET /v1/cert/*/verify    — VRS lookups
  GET /v1/health           — health check

API Key (X-AISeal-Key header):
  POST /v1/scan            — submit scans
  POST /v1/monitor/events  — SDK telemetry
  GET  /v1/scans/*         — retrieve your own scan history
  GET  /v1/vendor/me       — vendor account info
  POST /v1/cert/*/request-revoke — vendor self-revoke

Admin JWT (Authorization: Bearer {jwt}):
  POST /v1/admin/cert/issue
  POST /v1/admin/cert/revoke
  POST /v1/admin/vendor/*
  GET  /v1/admin/audit-log
```

API key format: `ask_live_{32-char-random}` (live) or `ask_test_{32-char-random}` (sandbox). Prefix allows instant identification of env. Stored as SHA-256 hash in DB — same model as Stripe.

### 5.2 Full API Specification

```yaml
openapi: "3.1.0"
info:
  title: AISeal Trust OS API
  version: "1.0"
  description: >
    The AISeal Trust OS API. Public registry queries require no auth.
    Scan submission and monitor ingestion require API key.
    Cert issuance and revocation require admin JWT.

servers:
  - url: https://api.aiseal.ai/v1

paths:

  # ─── REGISTRY ─────────────────────────────────────────────────────────────

  /registry/{vendor_id}:
    get:
      summary: Get vendor and all their certified products
      security: []
      parameters:
        - name: vendor_id
          in: path
          required: true
          schema:
            type: string
            description: vendor slug or UUID
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  vendor:       { $ref: '#/components/schemas/Vendor' }
                  products:
                    type: array
                    items: { $ref: '#/components/schemas/CertifiedProduct' }
        404: { description: Vendor not found }

  /registry/search:
    get:
      summary: Search the certified AI registry
      security: []
      parameters:
        - name: q
          in: query
          schema: { type: string }
          description: Full-text search across vendor, product, category
        - name: tier
          in: query
          schema:
            type: string
            enum: [certified, certified-plus, enterprise]
        - name: category
          in: query
          schema: { type: string }
          description: e.g. "Healthcare AI", "Customer Support AI"
        - name: status
          in: query
          schema:
            type: string
            enum: [active, expiring]
          default: active
        - name: page
          in: query
          schema: { type: integer, default: 1 }
        - name: per_page
          in: query
          schema: { type: integer, default: 20, maximum: 100 }
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  results:
                    type: array
                    items: { $ref: '#/components/schemas/CertifiedProduct' }
                  total: { type: integer }
                  page: { type: integer }
                  per_page: { type: integer }

  /registry/bulk-verify:
    post:
      summary: Bulk verify up to 100 cert IDs in one call
      description: Enterprise procurement use case — verify your entire AI vendor stack
      security: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [cert_ids]
              properties:
                cert_ids:
                  type: array
                  items: { type: string }
                  maxItems: 100
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  results:
                    type: object
                    additionalProperties:
                      $ref: '#/components/schemas/VerifyResponse'

  # ─── CERT LIFECYCLE ────────────────────────────────────────────────────────

  /cert/{cert_id}/verify:
    get:
      summary: Real-time cert status check (VRS / OCSP equivalent)
      description: >
        No auth required. Returns current status within 120s of any change.
        This is the hot path called by badges, procurement tools, SDK heartbeats.
      security: []
      parameters:
        - name: cert_id
          in: path
          required: true
          schema: { type: string }
      responses:
        200:
          content:
            application/json:
              schema: { $ref: '#/components/schemas/VerifyResponse' }
        404: { description: Unknown cert_id }

  /cert/{cert_id}/request-revoke:
    post:
      summary: Vendor-initiated revocation request
      security:
        - apiKey: []
      parameters:
        - name: cert_id
          in: path
          required: true
          schema: { type: string }
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [reason]
              properties:
                reason: { type: string }
      responses:
        202: { description: Request queued for admin review }
        403: { description: Cert does not belong to your vendor account }

  # ─── SCAN ──────────────────────────────────────────────────────────────────

  /scan:
    post:
      summary: Submit a prompt for OWASP LLM Top 10 scanning
      security:
        - apiKey: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [prompt]
              properties:
                prompt:
                  type: string
                  maxLength: 32768
                model:
                  type: string
                  description: Model identifier being tested
                  default: "claude-sonnet-4-6"
                scenario:
                  type: string
                  description: Optional context label
                product_id:
                  type: string
                  format: uuid
                  description: Link scan to a registered product
      responses:
        200:
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ScanResponse' }
        429: { description: Rate limit exceeded }

  /scan/{scan_id}:
    get:
      summary: Retrieve a completed scan result
      security:
        - apiKey: []
      parameters:
        - name: scan_id
          in: path
          required: true
          schema: { type: string, format: uuid }
      responses:
        200:
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ScanResponse' }
        403: { description: Scan belongs to different vendor account }
        404: { description: Scan not found }

  /scans:
    get:
      summary: List scan history for authenticated vendor
      security:
        - apiKey: []
      parameters:
        - name: product_id
          in: query
          schema: { type: string, format: uuid }
        - name: from
          in: query
          schema: { type: string, format: date-time }
        - name: to
          in: query
          schema: { type: string, format: date-time }
        - name: page
          in: query
          schema: { type: integer, default: 1 }
        - name: per_page
          in: query
          schema: { type: integer, default: 20, maximum: 100 }
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  scans:
                    type: array
                    items: { $ref: '#/components/schemas/ScanSummary' }
                  total: { type: integer }

  # ─── MONITOR ───────────────────────────────────────────────────────────────

  /monitor/events:
    post:
      summary: Ingest SDK telemetry events
      description: >
        High-volume endpoint. Accepts batches of up to 100 events.
        No raw prompts or responses — hashes only.
        SDK calls this on every monitored interaction.
      security:
        - apiKey: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [cert_id, events]
              properties:
                cert_id:
                  type: string
                sdk_version:
                  type: string
                events:
                  type: array
                  maxItems: 100
                  items: { $ref: '#/components/schemas/MonitorEvent' }
      responses:
        202: { description: Events accepted }
        401: { description: Invalid API key }
        422: { description: Validation error }

  /monitor/status/{cert_id}:
    get:
      summary: Get current monitor health for a certified product
      security:
        - apiKey: []
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  cert_id: { type: string }
                  monitoring_active: { type: boolean }
                  last_event_at: { type: string, format: date-time }
                  event_counts_24h:
                    type: object
                    properties:
                      clean: { type: integer }
                      warn: { type: integer }
                      blocked: { type: integer }
                  anomaly_score: { type: number }  # 0.0-1.0
                  alert_threshold: { type: number }

  # ─── WEBHOOKS ──────────────────────────────────────────────────────────────

  /webhooks:
    post:
      summary: Register a webhook endpoint
      security:
        - apiKey: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [url, events]
              properties:
                url: { type: string, format: uri }
                events:
                  type: array
                  items:
                    type: string
                    enum:
                      - cert.issued
                      - cert.expiring     # 30 days before expiry
                      - cert.expired
                      - cert.revoked
                      - cert.suspended
                      - scan.complete
                      - monitor.alert
      responses:
        201:
          content:
            application/json:
              schema:
                type: object
                properties:
                  webhook_id: { type: string }
                  secret: { type: string }
                    # HMAC signing secret — shown ONCE, store it

  # ─── ADMIN (internal) ─────────────────────────────────────────────────────

  /admin/cert/issue:
    post:
      summary: Issue a TrustCert (admin only — post-scan approval)
      security:
        - adminJwt: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [product_id, scan_id, tier]
              properties:
                product_id: { type: string, format: uuid }
                scan_id: { type: string, format: uuid }
                tier: { type: string, enum: [certified, certified-plus, enterprise] }
      responses:
        201:
          content:
            application/json:
              schema: { $ref: '#/components/schemas/CertDetail' }

  /admin/cert/revoke:
    post:
      summary: Revoke a TrustCert (admin only)
      security:
        - adminJwt: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [cert_id, reason]
              properties:
                cert_id: { type: string }
                reason: { type: string }
                evidence:
                  type: object
                  properties:
                    scan_ids: { type: array, items: { type: string } }
                    monitor_event_ids: { type: array, items: { type: string } }
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  cert_id: { type: string }
                  revoked_at: { type: string, format: date-time }
                  crl_updated: { type: boolean }

components:
  securitySchemes:
    apiKey:
      type: apiKey
      in: header
      name: X-AISeal-Key
    adminJwt:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:

    VerifyResponse:
      type: object
      properties:
        cert_id: { type: string }
        status:
          type: string
          enum: [good, revoked, expired, suspended, unknown]
        tier: { type: string }
        trust_score: { type: integer }
        product: { type: string }
        vendor: { type: string }
        issued_at: { type: string, format: date-time }
        expires_at: { type: string, format: date-time }
        revoked_at: { type: string, format: date-time }
        revocation_reason: { type: string }
        signature_valid: { type: boolean }
        next_update: { type: string, format: date-time }

    ScanResponse:
      type: object
      properties:
        scan_id: { type: string, format: uuid }
        score: { type: integer, minimum: 0, maximum: 100 }
        findings:
          type: array
          items: { $ref: '#/components/schemas/Finding' }
        model: { type: string }
        scenario: { type: string }
        prompt_length: { type: integer }
        categories_checked: { type: integer }
        latency_ms: { type: integer }
        timestamp: { type: string, format: date-time }
        certification_eligible: { type: boolean }
        cert_recommendation: { type: string, enum: [certified, certified-plus, enterprise, not-eligible] }

    Finding:
      type: object
      properties:
        category: { type: string }
        code: { type: string }
        status: { type: string, enum: [pass, fail, warning] }
        severity: { type: string, enum: [critical, high, medium, low, info] }
        detail: { type: string }
        nist:
          type: object
          properties:
            functions: { type: array, items: { type: string } }
            pillars: { type: array, items: { type: string } }
        mitre:
          type: array
          items:
            type: object
            properties:
              id: { type: string }
              name: { type: string }

    MonitorEvent:
      type: object
      required: [event_type, ts]
      properties:
        event_type:
          type: string
          enum: [threat_blocked, threat_warn, anomaly, health_ping]
        severity: { type: string }
        owasp_category: { type: string }
        prompt_hash: { type: string, description: SHA-256 of prompt }
        response_hash: { type: string, description: SHA-256 of response }
        latency_ms: { type: integer }
        region: { type: string }
        ts: { type: string, format: date-time }

    CertifiedProduct:
      type: object
      properties:
        cert_id: { type: string }
        vendor_name: { type: string }
        vendor_slug: { type: string }
        product_name: { type: string }
        product_version: { type: string }
        category: { type: string }
        tier: { type: string }
        trust_score: { type: integer }
        status: { type: string }
        issued_at: { type: string }
        expires_at: { type: string }
        registry_url: { type: string }
        badge_url: { type: string }
```

### 5.3 Rate Limiting

```
Tier              Scan RPM    Verify RPM    Monitor Events/min
──────────────────────────────────────────────────────────────
Unauthenticated     0           1000           0
Free API Key        10          1000          100
Paid API Key        100         1000         1000
Enterprise         1000          ∞           10000
```

Verify is high-limit because every badge load calls it. Scan is the expensive operation — rate-limited hard.

Implementation: Redis token bucket per `(key_id, endpoint)`. SlowAPI pattern already exists in `scanner/main.py` — extend it.

---

## PART 6: SDK — AISEAL MONITOR

### 6.1 npm Package

```typescript
// Package: aiseal-monitor
// Install: npm install aiseal-monitor

import { AISealMonitor } from 'aiseal-monitor';

// Initialization
const monitor = new AISealMonitor({
  certId: 'AC-2026-001',           // Required — your AISeal cert ID
  apiKey: process.env.AISEAL_KEY,  // Required — your vendor API key

  // Optional
  endpoint: 'https://api.aiseal.ai/v1',  // default
  region: 'us-west-2',                    // passed in telemetry, no routing effect
  sdkMode: 'observe',                     // 'observe' | 'enforce'
                                          // observe = emit events, don't block
                                          // enforce = block flagged requests
  flushInterval: 5000,       // ms — batch events before sending (default 5s)
  maxQueueSize: 1000,        // drop oldest if queue exceeds this
  offlineMode: 'queue',      // 'queue' | 'passthrough' | 'block'
                             // queue = store locally, flush on reconnect
                             // passthrough = allow traffic, log locally
                             // block = reject all traffic if cloud unreachable
  hashAlgorithm: 'sha256',   // prompt/response hashing — never raw text
  sampleRate: 1.0,           // 0.0-1.0, default 1.0 (monitor all traffic)
  onEvent: (event) => {},    // optional local callback
  onAlert: (alert) => {},    // called when SDK detects a threat
  onError: (err) => {},      // SDK error handler
});

// Initialize (verifies cert status, establishes connection)
await monitor.init();

// Usage Pattern 1: Wrap — intercept before/after LLM call
const result = await monitor.wrap(async () => {
  return await yourLlmClient.complete(prompt);
}, {
  prompt,
  model: 'claude-sonnet-4-6',
  userId: 'usr_abc123',    // hashed before transmission
  sessionId: 'sess_xyz',   // hashed before transmission
});
// result.allowed: boolean
// result.response: LLM response (if allowed)
// result.finding: Finding | null (if threat detected)

// Usage Pattern 2: Explicit check before LLM call
const check = await monitor.checkPrompt(prompt, {
  model: 'gpt-4o',
  context: 'customer-support',
});
if (!check.allowed) {
  return { error: 'Request blocked by AISeal Monitor', code: check.finding?.code };
}
const response = await yourLlmClient.complete(prompt);
await monitor.recordResponse(check.requestId, response);

// Usage Pattern 3: Emit custom events
monitor.emit({
  event_type: 'anomaly',
  severity: 'high',
  owasp_category: 'LLM06',
  metadata: { context: 'tool-use-excessive' },
});

// Lifecycle
monitor.pause();   // stop monitoring (maintenance mode)
monitor.resume();
await monitor.flush();  // force-send all queued events
await monitor.shutdown();
```

### 6.2 pip Package

```python
# Package: aiseal-monitor
# Install: pip install aiseal-monitor

from aiseal_monitor import AISealMonitor, MonitorConfig

# Initialization
monitor = AISealMonitor(
    cert_id="AC-2026-001",
    api_key=os.environ["AISEAL_KEY"],
    mode="observe",           # 'observe' | 'enforce'
    offline_mode="queue",     # 'queue' | 'passthrough' | 'block'
    flush_interval=5.0,       # seconds
    sample_rate=1.0,
)

# Context manager pattern
async with monitor.session(prompt=prompt, model="claude-sonnet-4-6") as session:
    response = await your_llm_client.complete(prompt)
    session.record_response(response)
    # Session auto-emits event on exit

# Decorator pattern (FastAPI / Flask compatible)
@monitor.protect(mode="enforce")
async def llm_endpoint(prompt: str) -> str:
    return await llm_client.complete(prompt)

# Sync version
with monitor.sync_session(prompt=prompt) as session:
    response = llm_client.complete(prompt)
    session.record_response(response)

# Manual emit
monitor.emit_event(
    event_type="threat_blocked",
    severity="critical",
    owasp_category="LLM01",
    prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
)

# Graceful shutdown
monitor.shutdown()
```

### 6.3 What the SDK Sends (Data Minimization)

```
NEVER sent:
  - Raw prompt text
  - Raw LLM response text
  - User PII
  - Authentication tokens

ALWAYS sent:
  - SHA-256(prompt)           -- for correlation, never reversible
  - SHA-256(response)         -- same
  - event_type                -- threat_blocked | threat_warn | anomaly | health_ping
  - severity
  - owasp_category (if applicable)
  - latency_ms
  - sdk_version
  - ts (UTC timestamp)
  - cert_id
  - region

OPTIONALLY sent (vendor-configurable):
  - model identifier
  - session_id (hashed)
  - user_id (hashed)
  - prompt_length (integer, not text)
  - response_length (integer)
```

The SDK's threat detection runs locally (same scanner.py logic compiled into the SDK) — the scan never leaves the customer's infrastructure. Only the result (pass/warn/block + hash) is transmitted.

### 6.4 Offline Mode Behavior

```
Cloud unreachable scenario:

mode=queue (default for Enterprise):
  - SDK stores events in local SQLite buffer (max 10,000 events)
  - Continues monitoring / enforcing locally
  - Retries cloud connection with exponential backoff (1s, 2s, 4s... max 60s)
  - On reconnect, flushes buffer in chronological order
  - If buffer full: drops oldest events, logs warning

mode=passthrough (default for Certified/Certified+):
  - Allows all traffic
  - Logs events locally to disk
  - Emits onError callback
  - Flushes on reconnect

mode=block (high-security deployments):
  - Rejects all LLM traffic while cloud unreachable
  - Returns 503 with header: X-AISeal-Status: offline
  - Logs locally
  - Sends alert to onAlert callback
```

### 6.5 SDK Health/Heartbeat

Every 60 seconds the SDK emits a `health_ping` event:

```json
{
  "event_type": "health_ping",
  "cert_id": "AC-2026-001",
  "sdk_version": "1.2.0",
  "events_since_last_ping": 847,
  "blocked_since_last_ping": 3,
  "queue_depth": 0,
  "cloud_connected": true,
  "ts": "2026-04-11T12:00:00Z"
}
```

If health pings stop arriving (cloud sees last ping > 5 min ago), Monitor status flips to "degraded" and fires a `monitor.degraded` webhook.

---

## PART 7: THE BADGE EMBED

### 7.1 JavaScript Snippet

Vendor puts this in their HTML:

```html
<!-- AISeal Trust Badge -->
<div id="aiseal-badge" data-cert="AC-2026-001"></div>
<script src="https://badge.aiseal.ai/v1/badge.js" async></script>
```

The badge.js script (~4KB gzipped):

```javascript
// badge.js behavior:
// 1. Reads data-cert attribute from the div
// 2. Fetches GET /v1/cert/{cert_id}/verify (from cache, sub-50ms)
// 3. Injects SVG badge into the div based on response
// 4. Badge shows: tier color + name + TrustScore + expiry status
// 5. On click: opens aiseal.ai/registry/{cert_id} in new tab
// 6. On hover: tooltip with full cert details
// 7. If status=revoked/expired: shows red "Certification Revoked" badge
// 8. If verify call fails: shows grey "Status Unknown" badge (fail-open)
// 9. Refreshes every 5 minutes (long-polls VRS)

// CSP-safe: no eval, no inline handlers, no cross-origin data sent
// No cookies, no tracking, no fingerprinting
```

### 7.2 Badge States

```
Active (Certified):      [ ✓ AISeal Certified     | 87 ]   green
Active (Certified+):     [ ✓ AISeal Certified+    | 91 ]   blue
Active (Enterprise):     [ ✓ AISeal Enterprise    | 94 ]   purple
Expiring (30 days):      [ ⚠ AISeal Certified     | 87 ]   amber
Expired:                 [ ✗ Certification Expired | -- ]   grey
Revoked:                 [ ✗ Certification Revoked | -- ]   red
Unknown/offline:         [ ? AISeal — Status Unknown ]      grey outline
```

### 7.3 Static Badge for Docs/Marketing

```
GET https://badge.aiseal.ai/v1/badge/{cert_id}.svg

Returns SVG badge image. For use in GitHub READMEs, PDFs, marketing decks.
Always shows live status (SVG is dynamically generated on each request).
```

```markdown
<!-- GitHub README -->
[![AISeal Certified](https://badge.aiseal.ai/v1/badge/AC-2026-001.svg)](https://aiseal.ai/registry/AC-2026-001)
```

---

## PART 8: SCANNING PIPELINE AT SCALE

### 8.1 Pipeline Architecture

```
Vendor submits POST /v1/scan
         │
         ▼
   API validates key, rate limit
         │
         ▼
   ScanJob created in PostgreSQL (status=queued)
         │
         ▼
   Job published to BullMQ (Redis-backed)
   → returns { scan_id, status: "queued", estimated_wait_ms: 800 }
         │
         ▼
   Worker pool (auto-scaled, 1-20 workers)
         │
         ├── Static analysis (scanner.py — runs in <100ms, in-process)
         │
         └── Dynamic analysis (optional, Enterprise cert path):
               → Isolated Docker container per scan
               → Spins up a sandboxed LLM proxy (not real LLM)
               → Runs red-team prompt suite against it
               → Max 60s wall time, then kill
               → Results written to S3
         │
         ▼
   ScanJob updated in PostgreSQL (status=complete, findings=JSONB)
         │
         ├── Webhook fired if vendor subscribed to scan.complete
         │
         └── SSE/polling response delivered to API caller
```

### 8.2 Avoiding API Credit Burn at Scale

For cert-level scanning (the expensive path):

```
Option A — Synthetic LLM (recommended for scale):
  Deploy a sandboxed "echo LLM" that returns scripted responses to known attack prompts.
  The scanner tests prompt patterns, not actual model behavior.
  Cost: ~$0/scan. Works for static analysis of 80% of OWASP categories.

Option B — Cached real calls (for dynamic verification):
  Hash the prompt + model combo.
  If exact hash exists in scan_cache (7-day TTL), return cached finding.
  Only call real LLM on cache miss.
  Cache hit rate in practice: ~60% (vendors re-test similar prompts).

Option C — Sampling:
  Dynamic LLM calls run on 10% of submitted scans (random sampling).
  Remaining 90% use static analysis + last-known dynamic result.
  Flag: scan.dynamic_verified: true | false on ScanResponse.

Cert-level scans always run Option B + Option C for the mandatory controls.
Free/API scans always run static only (Option A logic).
```

### 8.3 Scan Results Versioning

```
A scan from today vs 6 months ago:

scans table stores: findings (JSONB), score, scanner_version, model_tested, timestamp
scanner_version is semver of the scanner module (scanner.py) in use at scan time.

When scanner logic updates (new patterns added), scanner_version increments.
Historical scans preserve their original findings — no retroactive re-scoring.

Cert renewal: vendor must run a new scan under the current scanner_version.
If scanner_version >= cert.issued_scanner_version + 1 major version → renewal mandatory.

Diff view (roadmap): compare scan N vs scan N-1 findings for same product.
```

---

## PART 9: ENTERPRISE PROCUREMENT INTEGRATION

### 9.1 The Enterprise Use Case

An enterprise CISO with 47 AI vendors in their stack wants to:
- Require AISeal Cert in vendor questionnaires
- Verify all 47 vendors with one call
- Get notified automatically when any cert expires or is revoked

### 9.2 API Integration

```javascript
// Enterprise verification — one call for entire AI vendor stack
const response = await fetch('https://api.aiseal.ai/v1/registry/bulk-verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    cert_ids: [
      'AC-2026-001',  // Meridian Health — ClinicalAssist v3
      'AC-2026-003',  // Vantage Legal — DocReview AI
      // ... up to 100
    ]
  })
});

const { results } = await response.json();
// results: { 'AC-2026-001': { status: 'good', tier: 'enterprise', ... }, ... }

// Find any non-good statuses
const issues = Object.entries(results)
  .filter(([_, r]) => r.status !== 'good');
```

### 9.3 Procurement Tool Integration

```
Vendr / Zip / Coupa integration path (Phase 2 roadmap):

1. AISeal provides a public webhook subscription endpoint per enterprise account.
2. Enterprise registers their 47 cert IDs + their procurement tool webhook URL.
3. AISeal fires POST to that webhook on: cert.expiring, cert.expired, cert.revoked.
4. Enterprise procurement tool receives alert and auto-creates renewal ticket.

Webhook payload:
{
  "event": "cert.revoked",
  "cert_id": "AC-2026-001",
  "vendor_name": "Meridian Health Systems",
  "product_name": "ClinicalAssist v3",
  "revoked_at": "2026-04-10T14:22:00Z",
  "reason": "Runtime monitoring detected sustained LLM01 violations",
  "registry_url": "https://aiseal.ai/registry/AC-2026-001",
  "aiseal_signature": "HMAC-SHA256 of payload body with webhook secret"
}

Phase 1 (now possible):
  Enterprise registers via POST /v1/webhooks with their 47 cert IDs.
  No native Vendr/Zip/Coupa plugin required — webhook is universal.
```

---

## PART 10: INFRASTRUCTURE STACK

### 10.1 Cloud Provider: GCP (primary) + Cloudflare (edge)

**Why GCP over AWS:**
- Cloud HSM: GCP Cloud HSM is mature, well-priced, compliant (FIPS 140-2 Level 3)
- CloudSQL PostgreSQL: managed, point-in-time recovery, 99.99% SLA
- Cloud Run: serverless containers, scales to zero (cost efficiency at early stage)
- Workload Identity: cleaner than AWS IAM role management for service accounts
- BigQuery: telemetry analytics at scale without managing a data warehouse

**Cloudflare at the edge:**
- VRS responses cached at edge (~200 POPs globally) — latency SLA hit easily
- DDoS protection on public endpoints (registry, verify, badge)
- WAF rules on API endpoints
- CDN for badge.js and SVG badges

### 10.2 Service Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Cloudflare Edge                                                │
│  - badge.aiseal.ai   → badge.js + SVG serve + VRS cache        │
│  - api.aiseal.ai     → WAF + rate limit assist + DDoS          │
│  - crl.aiseal.ai     → CRL distribution (static, high cache)   │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│  GCP — us-central1 (primary) + us-east1 (DR)                   │
│                                                                 │
│  Cloud Run Services:                                            │
│  ├── api-gateway      (Next.js — existing Railway → Cloud Run)  │
│  ├── scanner-api      (FastAPI — existing Railway → Cloud Run)  │
│  ├── vrs-service      (FastAPI — new, hot path, 3+ instances)   │
│  ├── monitor-ingest   (FastAPI — new, high-volume write path)   │
│  ├── cert-service     (FastAPI — new, cert lifecycle)           │
│  ├── webhook-dispatch (FastAPI — new, async webhook delivery)   │
│  └── badge-service    (Go — new, ultra-low latency SVG serve)   │
│                                                                 │
│  Cloud SQL (PostgreSQL 15):                                     │
│  ├── aiseal_registry  (primary DB — registry, certs, scans)    │
│  └── Read replica in us-east1                                   │
│                                                                 │
│  Memorystore (Redis 7):                                         │
│  └── cert status cache + BullMQ scan job queue                 │
│                                                                 │
│  Cloud HSM:                                                     │
│  ├── aiseal-root-ca   (key version, NEVER extracted)           │
│  └── aiseal-int-ca    (signing key, accessed by cert-service)  │
│                                                                 │
│  Cloud Storage:                                                 │
│  ├── scan-artifacts/  (scan findings archives, 90-day retain)  │
│  └── crl/             (current.json, current.crl — public)     │
│                                                                 │
│  Cloud Tasks: renewal reminder jobs, CRL rebuild               │
│  BigQuery: monitor_events analytics (sink from Pub/Sub)        │
│  Secret Manager: API key salts, webhook HMAC secrets           │
└─────────────────────────────────────────────────────────────────┘
```

### 10.3 Migration Path: Railway → GCP

```
Phase 0 (NOW):     Railway — Next.js + FastAPI scanner. Zero infra.
Phase 1 (revenue): Railway → Cloud Run. Drop-in. Same containers.
                   Add: CloudSQL, Memorystore, Cloud HSM.
                   Add: VRS service, cert-service.
Phase 2 (scale):   Add monitor-ingest service. Add BigQuery sink.
                   Add webhook-dispatch. Add Cloudflare edge.
Phase 3 (enterprise): DR replica. CloudSQL HA. SLA documentation.
```

No rewrite required. The containers are already Docker-based. Railway is Cloud Run with a simpler billing model. The migration is a config change, not a code change.

### 10.4 Cost Model at 1,000 Certified Vendors

```
Assumptions:
- 1,000 active certs
- 50,000 badge verify calls/day
- 5,000 monitor events/day (Enterprise tier with SDK installed)
- 200 scans/month
- 1 TB storage/year (scan archives)

Monthly cost estimate (GCP):

Cloud Run (all services):     ~$120
CloudSQL PostgreSQL:          ~$180  (db-g1-small + storage)
Memorystore Redis:            ~$90   (1GB instance)
Cloud HSM:                    ~$300  (2 key versions)
Cloud Storage (1TB):          ~$25
BigQuery (analytics):         ~$30
Cloudflare Pro:               ~$20
Cloud Tasks / Pub/Sub:        ~$15
Misc (logs, monitoring):      ~$40
──────────────────────────────────
TOTAL:                        ~$820/month

Revenue model check:
  1,000 vendors × $299/year average = $299,000 ARR
  Infrastructure cost: ~$10K/year = 3.3% of revenue
  Gross margin: ~96% (excluding headcount)
```

---

## PART 11: SECURITY OF AISEAL ITSELF

### 11.1 Threat Model

AISeal is the single source of truth for AI trustworthiness. Compromise of the registry = ability to certify malicious AI systems or revoke legitimate ones. This makes AISeal a high-value target.

Specific threats:

```
T1: Registry tampering — attacker modifies cert status in PostgreSQL
T2: CA key compromise — attacker forges certificates
T3: API abuse — attacker revokes competitor certs
T4: Monitor data poisoning — attacker floods monitor events to trigger false revocations
T5: Badge spoofing — attacker serves fake badges without calling VRS
T6: Supply chain — attacker compromises scanner logic to pass bad actors
T7: Insider threat — AISeal employee modifies cert status
```

### 11.2 Controls

```
T1 — Registry Tamper:
  - PostgreSQL row-level security: cert records are append-only
  - Status changes ONLY via cert-service (no direct DB access from API gateway)
  - Every cert status change: audit_log entry (before/after state)
  - audit_log is INSERT-only (no UPDATE, no DELETE via application role)
  - Nightly hash chain over audit_log (like a mini blockchain — detects retroactive edits)
  - Read replica in us-east1 — divergence alerts

T2 — CA Key Compromise:
  - Root CA key: offline HSM, air-gapped, dual-person integrity for any operation
  - Intermediate CA key: Cloud HSM, never extracted, signing happens via HSM API
  - Key rotation: Intermediate CA rotated annually
  - If compromise detected: Root CA signs new Intermediate, all existing certs remain valid
    (they were signed by a valid Intermediate at time of issuance — revocation is by cert_id, not key)

T3 — API Abuse (unauthorized revocation):
  - Revoke endpoint requires admin JWT (not vendor API key)
  - Admin JWT: short-lived (15 min), issued via separate admin portal with MFA
  - Every revocation: dual-approval workflow (2 AISeal admins must approve)
  - Revocation webhook fires immediately — vendor is notified

T4 — Monitor Poisoning:
  - Monitor events are informational inputs to human review, not automated revocation triggers
  - Auto-revocation requires sustained threshold breach AND manual admin confirmation
  - Rate limiting on monitor/events endpoint per cert_id (prevents flood)
  - Anomaly scoring is statistical — one burst of events doesn't move the needle

T5 — Badge Spoofing:
  - badge.js always calls VRS — if it can't reach VRS, shows "Status Unknown"
  - Static SVG badge is dynamically generated per-request (no cached stale "Certified" image)
  - Verification instructions on badge click page: "Verify this badge at api.aiseal.ai/v1/cert/{id}/verify"

T6 — Scanner Supply Chain:
  - scanner.py is the single source of truth for detection logic
  - Changes require code review + test suite pass (13 red_team_prompts + CI)
  - Scanner version is stamped on every ScanResponse — cert references the scanner_version used
  - If scanner logic is found to have a false-negative: certs issued with that version are flagged for expedited renewal

T7 — Insider Threat:
  - audit_log is INSERT-only at DB role level (application cannot delete audit records)
  - All admin actions: dual-approval + audit log entry
  - Quarterly audit log review by a third party (ISO 42001 alignment)
  - AISeal itself maintains an active AISeal Enterprise cert (see below)
```

### 11.3 AISeal's Own AISeal Cert

AISeal certifies itself. This is non-negotiable — a security company that won't eat its own dog food is a liability.

```
Cert ID:  AC-AISEAL-001
Vendor:   AISeal, Inc.
Product:  AISeal ARIA (the AI assistant embedded in the platform)
Tier:     Enterprise
Scanner:  The same scanner.py that scans all other products
Renewal:  Quarterly (more aggressive than the 1-year standard)
Public:   Yes — listed prominently on the registry page

The ARIA assistant (app/api/aria/) must pass all mandatory controls.
If ARIA fails a re-scan, ARIA is patched before the cert is renewed.
Certification is never waived for internal products.
```

---

## PART 12: PHASED IMPLEMENTATION ROADMAP

### Phase 0 — What Exists Now (Railway)
- [x] FastAPI scanner (OWASP LLM01, LLM02, LLM04, LLM05, LLM06, LLM07)
- [x] TrustScore 0-100
- [x] Next.js frontend (Scan, Monitor demo, Registry demo)
- [x] Static registry with 4 seed entries
- [x] 3-tier cert framework defined (Certified, Certified+, Enterprise)
- [x] ARIA + Iris AI assistants
- [x] NIST AI RMF + MITRE ATLAS mappings on findings

### Phase 1 — Registry Goes Live (estimated: 2 months)
- [ ] PostgreSQL registry (vendors, ai_products, certs tables)
- [ ] Real cert issuance flow (admin-gated, manual approval)
- [ ] VRS endpoint (`GET /v1/cert/{id}/verify`) — backed by Redis cache
- [ ] Real registry page (pulls from DB, not hardcoded array)
- [ ] API key authentication (replace X-AISeal-Key shared secret with per-vendor keys)
- [ ] Webhook infrastructure (cert.issued, cert.expiring, cert.revoked)
- [ ] Badge embed — badge.js + SVG endpoint
- [ ] First 3-5 real certifications (friends/beta testers)

### Phase 2 — CA + Revocation (estimated: 4 months)
- [ ] CA key pair (Cloud HSM — Intermediate CA)
- [ ] Certificate signing (ECDSA-P256 over canonical payload)
- [ ] CRL generation + hosting (crl.aiseal.ai)
- [ ] Revocation workflow (manual admin, dual approval)
- [ ] Audit log (append-only, tamper detection)
- [ ] Bulk verify endpoint
- [ ] Scan history + versioning
- [ ] Renewal workflow

### Phase 3 — SDK + Monitor (estimated: 6 months)
- [ ] ghost99rt → production SDK (npm + pip packages)
- [ ] monitor/events ingest endpoint
- [ ] Monitor dashboard (real telemetry, not simulated)
- [ ] Anomaly scoring engine
- [ ] Enterprise tier (SDK required for Enterprise cert)
- [ ] BigQuery telemetry analytics

### Phase 4 — Enterprise Sales Features (estimated: 9 months)
- [ ] Enterprise bulk verification
- [ ] Procurement webhook integrations (Vendr/Zip API)
- [ ] SAML/SSO for enterprise vendor accounts
- [ ] SLA documentation (uptime, revocation lag)
- [ ] ISO 42001 compliance mapping (Phase 2 compliance)
- [ ] EU AI Act alignment

---

## APPENDIX A: CERT_ID FORMAT

```
AC-{YEAR}-{SEQ:03d}

AC        = AISeal Cert
2026      = year of issuance
001       = monotonic sequence within year (zero-padded to 3 digits)

Examples:
  AC-2026-001    (first cert issued in 2026)
  AC-2026-999    (999th cert in 2026)
  AC-2027-001    (sequence resets each year)

Special:
  AC-AISEAL-001  (AISeal's own self-cert — exempt from year prefix)
```

## APPENDIX B: SCANNER_VERSION FORMAT

```
{MAJOR}.{MINOR}.{PATCH}

MAJOR increments: new OWASP category added, existing category logic overhaul
MINOR increments: new patterns added to existing category
PATCH increments: false positive / false negative fix, no logic change

Current: 1.0.0 (scanner.py as of April 2026)

Cert renewal trigger: cert.scanner_version.MAJOR < current_scanner_version.MAJOR
```

## APPENDIX C: KEY DESIGN DECISIONS + RATIONALE

```
Decision: No raw prompt storage
Rationale: AISeal cannot be a liability. Storing customer prompts creates a massive
           data breach target. SHA-256 hashes are sufficient for correlation and
           anomaly detection. This is also a GDPR/CCPA moat — "we never see your prompts."

Decision: 120s max revocation lag (not instant)
Rationale: Instant revocation requires cache invalidation at global CDN edge, which
           either requires Cloudflare Enterprise ($$$) or accepting a brief window.
           120s is equivalent to OCSP with max_age=60s. Acceptable for the threat model.
           Emergency revocation bypasses CDN cache via Cloudflare Cache Purge API.

Decision: ECDSA-P256 over RSA-2048
Rationale: Smaller signature (64 bytes vs 256 bytes), faster verification,
           equivalent security at current threat levels, better mobile performance.
           Same choice made by modern WebPKI.

Decision: Dual-approval for revocation
Rationale: Wrongful revocation is catastrophic for the vendor (their product suddenly
           shows as "Revoked" on every badge embed). Must be human-gated.
           The risk of false revocation > risk of delayed legitimate revocation.

Decision: Local scan execution in SDK (not cloud-side)
Rationale: Latency. A round-trip to AISeal cloud on every LLM call adds 50-200ms.
           Running scanner.py locally adds ~5ms. Only the result (hash + event_type)
           is transmitted. This also works offline.

Decision: GCP over AWS
Rationale: Cloud HSM pricing, Cloud Run + CloudSQL integration simplicity,
           BigQuery for analytics without additional infrastructure.
           AWS is fine too — this is preference, not lock-in.
```

---

*End of document. Version 1.0. Build from this.*
