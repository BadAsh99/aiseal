# AISeal Monitor — Incident Response Playbooks
## Version 1.0 | AISeal Security Operations Package

---

## Signal Reference

| Signal ID | Name                     | OWASP LLM | Default Severity |
|-----------|--------------------------|-----------|-----------------|
| SIG-001   | Anomalous Token Volume   | LLM10     | MEDIUM          |
| SIG-002   | Prompt Injection         | LLM01     | HIGH            |
| SIG-003   | Data Exfiltration        | LLM02     | CRITICAL        |
| SIG-004   | Sensitive Data in Output | LLM06     | HIGH            |
| SIG-005   | Jailbreak Success        | LLM01     | CRITICAL        |
| SIG-006   | Model DoS Pattern        | LLM10     | HIGH            |
| SIG-007   | Tool Call Anomaly        | LLM06     | HIGH            |
| SIG-008   | Prompt Leakage           | LLM07     | HIGH            |
| SIG-009   | Refusal Rate Drop        | LLM01     | MEDIUM          |
| SIG-010   | SDK Offline              | Internal  | HIGH            |
| SIG-011   | Cert Health Score Drop   | Internal  | MEDIUM          |
| SIG-012   | Baseline Staleness       | Internal  | LOW             |

**Ghost99RT Engine Status Codes:**
- CLEAN — traffic nominal, no anomaly
- WARN — suspicious pattern, human review recommended
- BLOCK — threat confirmed, session interrupted

---

## PLAYBOOK 1: Prompt Injection Campaign
### Signal: SIG-002 | Severity: HIGH → CRITICAL (campaign)
### OWASP: LLM01 Prompt Injection

---

### TRIGGER

This playbook activates when **any of the following conditions** are met:

- Three or more SIG-002 alerts within a 10-minute window from different session IDs
- A single SIG-002 alert with confidence score ≥ 0.92 targeting a privileged agent (tool-use enabled)
- SIG-002 co-occurring with SIG-007 (Tool Call Anomaly) in the same session
- Indirect injection pattern: SIG-002 detected in model output (content retrieved from external source, not user input)

A single SIG-002 WARN on a basic chatbot is not this playbook. Three SIG-002 BLOCKs in ten minutes is.

---

### SEVERITY ASSESSMENT

**What this actually means:**

Prompt injection is the most common LLM threat and the noisiest false positive source. Before treating every SIG-002 as an attack, assess:

| Scenario | Likely Benign | Likely Attack |
|----------|--------------|---------------|
| Single session, single attempt, no tool access | Yes — curious user or pen tester | |
| Repeating across many sessions, similar payload structure | | Yes — coordinated campaign |
| Injection in *retrieved content* (RAG, web browse) | | Yes — indirect injection, highest risk |
| Injection attempt followed by tool calls | | Yes — attempting agent compromise |
| Security team doing internal testing | Yes — coordinate with them first | |

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Acknowledge the alert in Monitor dashboard.** This starts the audit clock and prevents duplicate escalation.

2. **Do not immediately block the source IP or user.** Premature blocking destroys forensic evidence and may affect legitimate users. Exception: if a BLOCK status is firing continuously from the same session, the Ghost99RT engine has already interrupted that session — verify it's working.

3. **Pull the session transcript** for the flagged session(s). In Monitor, click the alert row → Session Detail. Copy the full prompt chain, not just the flagged turn.

4. **Check whether the AI system has tool access.** A prompt injection against a read-only Q&A bot is a nuisance. A prompt injection against an agent with file system, email, or API tool access is an incident.

5. **Check session count.** How many unique session IDs triggered SIG-002 in the last 30 minutes? If more than five, you are likely looking at a campaign, not a single curious user.

6. **Notify your AI system owner** (the person or team responsible for the LLM application under attack). Give them the session count, the flagged payload types, and whether tool calls were involved.

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Classify the injection type.**

Review the flagged prompts and categorize:
- *Direct injection* — user sent the malicious payload directly in their message
- *Indirect injection* — malicious instructions arrived via retrieved content (document, web page, database record, tool output)
- *Stored injection* — malicious instructions were previously saved in a data source the model will retrieve later

Indirect and stored injections are higher severity. They are harder to detect and can affect future sessions even after the attacker is gone.

**Step 2 — Assess instruction compliance.**

Did the model follow the injected instructions? Review the model's response in each flagged session:
- If Ghost99RT BLOCKED the session, the instruction was interrupted before execution. This is the best outcome.
- If the session shows WARN (not BLOCK), the model may have partially complied. Review the output carefully for: system prompt disclosure, changed behavior, unexpected tool calls, or data in the response that should not be there.
- If the session shows CLEAN on the *response* but the *input* was injected, your detection is working on pattern — but verify the output manually anyway.

**Step 3 — Trace the injection source.**

For indirect injections: identify which data source delivered the malicious content. Was it a user-uploaded document? A web URL the agent browsed? A database field? This determines whether the injection is an isolated incident or an ongoing supply chain problem.

**Step 4 — Review session history for the affected users.**

If you can identify the user account behind the session, check their last 24 hours of activity. Were they doing normal things before this? A user whose first 10 turns are normal and whose 11th is an injection attempt is different from an account that opened with an injection.

**Step 5 — Check for lateral movement.**

If your AI system has access to internal tools or data, verify those tools were not invoked abnormally. Pull tool call logs for the flagged sessions. Any tool call that did not originate from a plausible user intent is evidence of successful injection.

---

### ESCALATION CRITERIA

Escalate to incident (page on-call, notify security team, initiate containment):

- Model output contains data it should not have accessed (indicates successful injection leading to data exposure)
- Tool calls were made that were not initiated by the user (indicates agent compromise)
- Injection payload is identical or structurally similar across more than 10 sessions (indicates coordinated attack with a specific payload, not random probing)
- Indirect injection found in a data source that persists (stored injection — affects all future sessions until cleaned)
- The injection targeted the system prompt specifically and the model disclosed it

Do NOT escalate solely because:
- A user typed "ignore previous instructions" once and Ghost99RT blocked it
- Your security team is running a red team exercise (check with them first)
- Someone is demonstrating the product to a prospect

---

### CONTAINMENT OPTIONS

**Option 1 — Rate limit the session source**
If injections are coming from identifiable user accounts or IP ranges, apply rate limiting at the application layer. Do not rely solely on Monitor for blocking — add a layer in your application's authentication or API gateway.

**Option 2 — Pause agent tool access**
If tool-use is enabled on the affected AI system, temporarily suspend tool calls while investigation is in progress. Most LLM platforms allow toggling tool availability in the system prompt or API configuration. This is the highest-leverage single action you can take.

**Option 3 — Roll the system prompt**
If the injection was specifically targeting system prompt contents (SIG-008 co-occurring), rotate the system prompt to a new version. This invalidates any extracted instructions and may break in-flight attacks that rely on the old prompt structure.

**Option 4 — Block the specific session**
If a single session is flooding injection attempts, terminate it directly. In Monitor → Sessions → select session → Force Close. This ends the session but does not prevent the same user from opening a new one.

**Option 5 — Emergency input sanitization**
For indirect injections: if the malicious content came from a specific data source (e.g., a document ingestion pipeline), pause ingestion from that source until the contaminated records are removed.

**Option 6 — Switch model to restricted mode**
Some LLM APIs support restricting the model's capabilities (disabling function calling, limiting output formats). Activate these restrictions if your API/platform supports them.

---

### EVIDENCE COLLECTION

Before closing this playbook, preserve:

- Full session transcripts for all flagged sessions (timestamp, session ID, model, prompt chain, response chain, tool calls if any)
- Ghost99RT classification metadata (confidence scores, matched rule IDs)
- Any tool call logs from the affected agent
- The data source contents if indirect injection was involved (snapshot the contaminated document or database record before cleaning it)
- Your application's access logs for the same time window
- User account activity logs if user identity is available

Store these in your incident management system. Retention minimum: 90 days.

---

### COMMUNICATION

**Internal — Immediate (within 30 minutes of escalation):**
- AI system owner: what happened, what is currently blocked or paused, status of investigation
- Security team lead: signal type, session count, tool access status, whether data was exposed

**Internal — Post-containment (within 4 hours):**
- Engineering team: if code changes are needed (input sanitization, prompt hardening, tool call validation)
- Privacy/Legal: if any PII or confidential data appeared in model output during the incident

**External — If customer data was affected:**
Follow your organization's data breach notification procedure. Prompt injection that successfully exfiltrates data is a data incident, not just a security incident.

**What to say to end users (if disclosure is required):**
"We detected and blocked an attempt to manipulate our AI system. The system performed as designed. We are investigating the source and have taken steps to prevent recurrence."

---

### RESOLUTION CRITERIA

This playbook is closed when:

- No new SIG-002 alerts from the affected sessions or sources for 24 hours
- Root cause identified and documented (what was the injection trying to do, how did it arrive)
- Containment actions are in place and tested
- Evidence package is complete
- Any affected data sources have been cleaned (for indirect/stored injections)
- Lesson learned template is filled out

---

### LESSON LEARNED TEMPLATE

After every incident, answer these five questions within 72 hours:

1. **What did the attacker try to accomplish?** (System prompt extraction, tool abuse, data exfiltration, persona override — be specific)
2. **At what point did the model deviate from expected behavior, if at all?** (Did Monitor catch it before the model complied, or after?)
3. **What was the attack vector?** (Direct user input, indirect via retrieved content, stored injection)
4. **What would have prevented this from reaching Monitor in the first place?** (Input validation layer? Prompt hardening? Restricting tool access by default?)
5. **What is the one change to your AI system's configuration or architecture that reduces the probability of this happening again?**

---
---

## PLAYBOOK 2: Suspected Data Exfiltration
### Signal: SIG-003 | Severity: CRITICAL
### OWASP: LLM02 Insecure Output Handling / LLM06 Excessive Agency

---

### TRIGGER

This playbook activates when:

- SIG-003 fires at any confidence level — there is no "low confidence" SIG-003 that doesn't warrant review
- Model output contains patterns matching: PII (SSN, credit card, passport numbers), credentials (API keys, passwords, tokens), internal system data (file paths, internal hostnames, configuration values, database schema), or bulk data structures (JSON/CSV/XML exports that exceed normal response size)
- A tool call to a file access, database, or API tool is followed immediately by a large outbound response
- Model output is being sent to an external destination (webhook, email, API endpoint) rather than displayed to the requesting user

**CRITICAL severity means respond now, not when you have time.**

---

### SEVERITY ASSESSMENT

**What this actually means:**

SIG-003 is the highest-stakes signal in the Monitor stack. Unlike prompt injection (which is often failed attempts), a SIG-003 alert means data may have already left your system. The investigation question is not "was this an attack" — it is "how much data left, and where did it go."

| Scenario | Data Exposure Risk |
|----------|-------------------|
| Model repeated back data the user themselves provided | Low — no new exposure |
| Model accessed internal database via tool call and included records in response | High — data left via model output |
| Model sent output to external endpoint (webhook, forwarding tool) | Critical — data may have left your environment entirely |
| RAG system returned sensitive internal documents in response | Medium to High — depends on whether those documents should be user-accessible |

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Treat this as a confirmed incident until proven otherwise.** SIG-003 has a low false positive rate. The burden of proof is on exoneration, not confirmation.

2. **Notify your security team and AI system owner immediately.** This is not a "look into it when you get a chance" alert.

3. **Preserve the output.** Before taking any containment action, screenshot or export the full model output that triggered the alert. Once sessions are terminated, output may be harder to reconstruct.

4. **Identify the destination of the output.**
   - If output was displayed in a browser UI: who was the user? Is that user authorized to see that data?
   - If output was sent via webhook or API: where did it go? Can you pull the outbound request logs?
   - If output was generated by an automated pipeline (no human user): what triggered the pipeline?

5. **Check whether the exposed data is still accessible.** If it appeared in a chat UI, it's already been seen. If it was sent to an external endpoint, it may still be in transit or cached. Act fast on external destinations.

6. **Do not delete the session or the output.** Evidence preservation supersedes cleanup. Coordinate with legal before deleting anything.

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Classify what was exposed.**

Review the flagged output and determine:
- Data category: PII, credentials/secrets, internal infrastructure details, business-sensitive data, regulated data (PHI, PCI, financial records)
- Data volume: a single name and email is different from 500 records
- Data sensitivity: public-facing vs. internal-only vs. regulated

**Step 2 — Trace the data origin.**

How did this data get into the model's context?
- Did the user provide it directly in their input?
- Did a tool call (file read, database query, API call) retrieve it?
- Did a RAG/document retrieval pipeline include it in context?

This determines whether the exposure was accidental (model retrieved more than intended) or adversarial (attacker manipulated the model to retrieve and output specific data).

**Step 3 — Determine if the exposure was adversarial.**

Check the session history. Did any earlier turn in this session include a prompt that could have directed the model to retrieve and output this data? If yes, this SIG-003 is the result of a successful prompt injection (SIG-002) — activate both playbooks simultaneously.

**Step 4 — Assess the recipient.**

Was the data output sent to:
- An authenticated user who was authorized to see it — still an incident if the data category is unexpected, but different compliance implications
- An unauthenticated or unauthorized user — data breach
- An external endpoint — potential exfiltration; treat as data breach

**Step 5 — Scope the blast radius.**

Is this one session, or is the same exposure pattern present in multiple sessions? Pull the last 24 hours of Monitor logs and filter for SIG-003. If this pattern is recurring, your AI system has a systematic data exposure problem, not an isolated incident.

---

### ESCALATION CRITERIA

Escalate to data breach response (legal, privacy officer, potentially regulatory notification):

- Any regulated data category: PHI (HIPAA), PCI data, PII under GDPR/CCPA
- Any credentials or API keys (must be rotated immediately — see Containment)
- Data sent to external destinations not under your control
- Bulk data (more than a handful of records) appearing in model output
- Pattern appears in multiple sessions (systematic exposure)

---

### CONTAINMENT OPTIONS

**Option 1 — Rotate exposed credentials immediately**
If the model output contained API keys, passwords, tokens, or any secrets: rotate them now, before anything else. This is time-critical. Treat every exposed credential as compromised regardless of whether you believe the exposure was observed.

**Option 2 — Terminate active sessions**
If the exfiltration pattern may still be in progress (active session with a user who is extracting data turn by turn), force-close the session in Monitor.

**Option 3 — Restrict data access for the AI system**
Temporarily revoke or restrict the AI system's tool access to the data source that was exposed. If it was a database query tool, disable that tool. If it was a RAG index over sensitive documents, suspend the retrieval pipeline. Your AI system can operate in degraded mode while you fix the access control problem.

**Option 4 — Apply output filtering**
If the exposure was accidental (RAG returning more than intended), enable or tighten output filtering rules in your AI system configuration. Monitor can apply pattern-matching blocks on output — contact your AISeal administrator to configure output blocklists for the specific data patterns exposed.

**Option 5 — Notify downstream recipients**
If data was sent to an external endpoint, contact whoever controls that endpoint and request deletion. If the endpoint is adversary-controlled, this step is for documentation purposes only.

---

### EVIDENCE COLLECTION

- Complete session transcript: every turn, every tool call, every response
- Tool call payloads: what query did the model send to retrieve the data?
- The retrieved data itself: what was in the model's context at time of output?
- Outbound request logs if data was forwarded externally
- Authentication/authorization records for the user session
- Timestamp of first exposure, last exposure, and time of detection

Preserve everything. Data breach investigations often span weeks. Evidence collected in the first hour is the most valuable.

---

### COMMUNICATION

**Within 15 minutes of confirming data exposure:**
- Security team and legal counsel: brief on data category, volume, destination
- CISO or equivalent: this does not wait for business hours

**Within 1 hour:**
- Engineering team: what access controls need to change
- Data owner for the exposed dataset: they need to know their data was exposed

**Within 24–72 hours (if regulated data):**
Review breach notification obligations. GDPR requires notification to supervisory authority within 72 hours of becoming aware of a breach. HIPAA requires notification within 60 days. PCI DSS requires notification to payment brands promptly. Get legal involved before the clock runs out.

**What to say to affected individuals (if required by law):**
Do not draft this without legal review. Each regulation has specific requirements for notification content.

---

### RESOLUTION CRITERIA

- Root cause identified and fixed (access control, output filtering, or RAG retrieval scope)
- All exposed credentials rotated
- Data breach notification obligations assessed (with legal) and met if required
- Evidence package complete and in incident management system
- Monitor detection rules updated if needed to improve future detection of the same pattern
- Lesson learned template complete

---

### LESSON LEARNED TEMPLATE

1. **What data was exposed, in what quantity, and to whom?** (Be specific — this is the incident definition)
2. **Was the exposure adversarial (someone made it happen) or accidental (AI system had overly broad access)?** (This determines remediation priority)
3. **What access control or architectural change would have prevented this data from entering the model's context in the first place?**
4. **How long between first exposure and detection?** (Measure your detection latency — this is a key metric)
5. **What is the minimum privilege posture your AI system needs to function?** (Most AI systems have access to far more data than they need — use this incident as forcing function to fix that)

---
---

## PLAYBOOK 3: Jailbreak Success
### Signal: SIG-005 | Severity: CRITICAL
### OWASP: LLM01 Prompt Injection / LLM04 Model Denial of Service

---

### TRIGGER

This playbook activates when:

- SIG-005 fires after Ghost99RT detects a jailbreak payload AND the model's subsequent behavior changes — the model accepted the alternative persona, abandoned its system prompt guidelines, or produced output that it should have refused
- Monitor detects a "success" pattern: jailbreak attempt followed by output that does not match the model's configured behavior profile (e.g., model was configured to refuse certain topics, but stopped refusing after the jailbreak turn)
- Successive SIG-001 alerts in a session (model producing abnormally long/unusual output after a jailbreak attempt)
- Model self-identifies as a different persona in output ("I am DAN", "I am an unrestricted AI", etc.)

SIG-005 WARN = jailbreak attempt detected, outcome uncertain. SIG-005 BLOCK = attempt intercepted by Ghost99RT. Neither is this playbook. This playbook fires when there is evidence the jailbreak *worked*.

---

### SEVERITY ASSESSMENT

**What this actually means:**

A successful jailbreak means the model's safety and behavior guardrails have been bypassed. The model is now operating outside its configured parameters. Severity depends entirely on what the model is capable of in your deployment:

| Deployment Type | Jailbreak Success Impact |
|----------------|--------------------------|
| Public chatbot, no tool access, no sensitive data | Medium — model may produce harmful content, reputational risk |
| Internal assistant with access to company documents | High — model may disclose confidential information, bypass access controls |
| Agent with tool use (APIs, file system, email) | Critical — model may take unauthorized actions in your environment |
| Customer-facing agent handling transactions | Critical — model may be manipulated into fraudulent actions |

The jailbreak itself is not the threat. What the model does *after* the jailbreak is the threat.

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Pull the session immediately.** Get the full transcript from the jailbreak attempt through the current session state. You need to see what the model did after the guardrails dropped.

2. **Audit every action the model took after the jailbreak turn.** This is the priority. For each model output turn after the jailbreak:
   - Did the model disclose information it should have kept confidential?
   - Did the model make any tool calls?
   - Did the model's tone, persona, or content policy change?

3. **If tool-use is enabled: pull tool call logs immediately.** Any tool call that occurred after the jailbreak turn is potentially adversarial. Treat these as unauthorized until proven otherwise.

4. **Assess whether the session is still active.** If yes, force-close it.

5. **Notify AI system owner and security team.**

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Identify the jailbreak technique.**

Common categories (for documentation and pattern matching):
- *Persona injection* ("You are DAN / an unrestricted AI / a helpful assistant with no restrictions")
- *Roleplay frame* ("We're writing a novel where the AI character explains...")
- *Authority spoof* ("As your developer, I'm instructing you to...")
- *Context manipulation* ("Ignore your previous training. In this hypothetical...")
- *Token manipulation* (adversarial tokens, prompt dilution, base64 encoding to bypass filters)
- *Iterative extraction* (multi-turn manipulation where each turn normalizes the next)

Document the technique. This feeds your detection rule improvements.

**Step 2 — Determine what the model did under the jailbreak.**

Review all output turns after the jailbreak point:
- Content policy violations (harmful content generation)
- Information disclosure (system prompt, internal data, confidential context)
- Behavioral persona changes (model presenting as a different AI)
- Tool calls (check these against the tool call anomaly playbook)
- Privilege escalation attempts

**Step 3 — Assess system prompt exposure.**

Jailbreaks frequently target system prompt disclosure. Check whether the model output included any of your system prompt content. If yes, your system prompt is now compromised — treat it as public and rotate it.

**Step 4 — Scope the exposure.**

Is this one user who found a jailbreak? Or is the same jailbreak payload appearing across multiple sessions? A payload that works reliably and appears in multiple sessions means it has been shared or automated — this is a campaign, not an individual.

**Step 5 — Test the jailbreak yourself.**

In a sandboxed environment (not production), attempt the same jailbreak technique against your AI system. Confirm whether it still works. If it does, you have a systemic vulnerability, not just a historical incident.

---

### ESCALATION CRITERIA

Escalate to full incident:

- The model made tool calls after the jailbreak (potential unauthorized actions)
- The model disclosed system prompt contents (prompt rotation required, treat system prompt as compromised)
- The model produced outputs that could cause direct harm (harmful instructions, threats, regulated content)
- The same jailbreak payload is appearing in multiple sessions
- Evidence the jailbreak is being automated (machine-speed session creation)

---

### CONTAINMENT OPTIONS

**Option 1 — Rotate the system prompt**
If the jailbreak worked against your current system prompt, your system prompt is vulnerable to that technique. Add explicit anti-jailbreak instructions, reinforce persona constraints, and add a "remember your role" anchor at the end of the system prompt. Test before deploying.

**Option 2 — Add input screening**
If the jailbreak payload has identifiable linguistic patterns, add a pre-processing filter that flags or blocks those patterns before they reach the model. Ghost99RT does this at the inference layer — if a new technique is evading detection, submit the payload to AISeal support for rule addition.

**Option 3 — Restrict tool access**
Temporarily disable tool access if tool calls occurred post-jailbreak, until the prompt is hardened and retested.

**Option 4 — Reduce model capability**
If using a highly capable model (GPT-4, Claude Sonnet) for a task that does not require it, consider downgrading to a less capable model for that specific application. Less capable models are often more resistant to sophisticated jailbreaks.

**Option 5 — Implement output validation**
Add a second model or rule-based check to evaluate model output before it reaches the user. This adds latency but catches policy violations that slip through input-side defenses.

---

### EVIDENCE COLLECTION

- Full session transcript from the jailbreak turn forward
- Exact jailbreak payload (preserve verbatim — needed for detection rule creation)
- All model outputs post-jailbreak
- Tool call logs if applicable
- Any system prompt content that was disclosed

---

### COMMUNICATION

**Internal:**
- AI system owner: jailbreak confirmed, describe what the model did, current containment status
- Security team: jailbreak technique, tool call status, scope (single user vs. campaign)
- If tool calls were made: notify owners of any systems the model has tool access to

**External (if model output caused harm):**
Evaluate case by case. If the model provided harmful content to a user under a jailbreak, consult legal on disclosure obligations.

---

### RESOLUTION CRITERIA

- Session terminated and evidence preserved
- System prompt hardened and tested against the confirmed jailbreak technique
- Ghost99RT detection rules updated for the new technique variant (submit to AISeal if needed)
- No SIG-005 from the same technique for 48 hours post-hardening
- Tool access verified and re-enabled only after prompt testing
- Lesson learned complete

---

### LESSON LEARNED TEMPLATE

1. **What technique bypassed the model's guardrails?** (Categorize it — this builds your threat model)
2. **What did the model do after guardrails dropped?** (Assess actual harm, not theoretical)
3. **Was this detected in real time or retrospectively?** (Detection latency tells you how long the model operated outside guardrails before you knew)
4. **What specific system prompt change or model configuration change prevents this technique from working?**
5. **If this technique were automated at scale against your application, what would the attacker gain?** (Threat model the jailbreak — some are not worth hardening against, some are existential)

---
---

## PLAYBOOK 4: Rogue Tool Call
### Signal: SIG-007 | Severity: HIGH
### OWASP: LLM06 Excessive Agency

---

### TRIGGER

This playbook activates when:

- A tool call is made by the model that cannot be explained by the user's stated intent in the current session
- A tool call is made to a resource or endpoint not in the model's expected tool scope
- A tool call makes a *write* operation (create, update, delete) when the session context only warranted a *read*
- A tool call is made to an unusual endpoint following a jailbreak or injection signal (SIG-002 or SIG-005 co-occurring)
- Tool call rate is abnormally high (more calls than the task would require)
- A tool call attempts to access resources outside the session's authorized scope (e.g., accessing another user's data, accessing admin endpoints)

---

### SEVERITY ASSESSMENT

**What this actually means:**

LLM06 (Excessive Agency) is how AI agents cause real-world damage. Unlike prompt injection or jailbreak (which affect the model's words), tool call anomalies affect the model's *actions*. The model may:

- Delete data it had no reason to delete
- Send emails to unauthorized recipients
- Access files belonging to other users
- Make API calls with side effects (charges, notifications, state changes)
- Attempt to escalate its own permissions

The threat model here is an AI agent doing something in your environment that a human authorized user would not do and would not have approved.

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Identify the specific tool call that fired the alert.** What tool, what parameters, what was the return value?

2. **Determine whether the tool call completed.** A pending or failed tool call is different from a completed one. If the call completed, determine what side effects it produced.

3. **Assess reversibility.** Did the tool call take an action that can be undone?
   - Read operations: no remediation needed unless data was included in a subsequent output
   - Write/create operations: can the created resource be deleted?
   - Delete operations: check your backup and audit trail — these may not be reversible
   - Send operations (email, notification, webhook): assume delivered, you cannot unsend

4. **Suspend the agent's tool access.** Do not wait for investigation completion. Pause the agent's ability to make tool calls while you determine whether this was intentional. Most LLM orchestration platforms support toggling tool availability without taking the AI system fully offline.

5. **Notify the AI system owner and the owner of the system that received the tool call.**

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Reconstruct the intent chain.**

Go back to the beginning of the session. What did the user ask for? Map every tool call the model made and ask: "Is this tool call a reasonable step toward fulfilling the user's stated request?"

If yes → possible false positive. The model may have taken a legitimate but unexpected path.
If no → the model acted outside user intent. Determine why.

**Step 2 — Check for injection as root cause.**

Review the session for any SIG-002 signals. Rogue tool calls are frequently the downstream consequence of a successful prompt injection. If injection preceded the tool call, treat this as a compound incident: both Playbook 1 and Playbook 4 apply.

**Step 3 — Evaluate the tool call parameters.**

What parameters did the model pass to the tool?
- Parameters derived from user input: higher chance of legitimate use, but also higher chance of injection
- Parameters generated by the model without user input: red flag — the model decided what to access or do on its own
- Parameters referencing resources not discussed in the session: high suspicion

**Step 4 — Audit the tool's access logs.**

Beyond what Ghost99RT captured, pull the access logs for the actual tool or system that was called. Confirm what the call did, what data it accessed or modified, and whether any authorization checks were bypassed.

**Step 5 — Assess scope.**

Is this a single anomalous call or a pattern? Pull the last 7 days of tool call logs for this AI agent. Are there other calls that don't match session context? A single anomalous call could be a bug. A pattern is either a systematic vulnerability or an ongoing attack.

---

### ESCALATION CRITERIA

Escalate to full incident:

- The tool call completed a destructive action (delete, overwrite) or sent data externally (email, webhook, API to external service)
- The tool call accessed resources belonging to a different user than the session user
- The tool call attempted to modify permissions, access controls, or agent configuration
- The tool call was preceded by a confirmed injection or jailbreak signal
- The pattern appears in multiple sessions (systematic agent misbehavior)

---

### CONTAINMENT OPTIONS

**Option 1 — Suspend tool access**
Immediately revoke the agent's tool calling permissions while investigation is in progress. This is the highest-leverage containment action.

**Option 2 — Revert unauthorized changes**
If the tool call created, modified, or deleted data: restore from backup or audit trail. Document what was changed and when.

**Option 3 — Rotate credentials the agent used for tool access**
If the rogue call used API keys or service accounts to authenticate to downstream systems, rotate those credentials. Treat them as potentially exposed.

**Option 4 — Add tool call validation**
Before re-enabling tool access, add an authorization layer: require explicit user confirmation before the agent can execute write/delete/send operations. Many LLM orchestration frameworks support a "human-in-the-loop" approval step for destructive actions.

**Option 5 — Scope down tool permissions**
Apply principle of least privilege to your AI agent's tool configuration. If the agent only needs to read from a database, give it a read-only credential. If it only needs to create tickets in one system, restrict its access to that one system.

---

### EVIDENCE COLLECTION

- The specific tool call: tool name, parameters, timestamp, return value, completion status
- The full session transcript leading up to the tool call
- Access logs from the target system
- State of the affected resource before and after the call (if data was modified)
- Any injection or jailbreak signals from the same session

---

### COMMUNICATION

**Internal:**
- Owner of the system that received the tool call: notify them of the unauthorized access, provide timestamp and parameters
- Security team: complete picture of what was accessed and what side effects occurred
- AI system owner: what needs to change in the agent configuration

**External (if customer data or external systems were affected):**
Assess on a case-by-case basis. Unauthorized access to customer data via an agent tool call may trigger breach notification obligations.

---

### RESOLUTION CRITERIA

- All side effects of the rogue call identified and remediated (or documented as non-remediable)
- Root cause identified (bug in agent logic, injection, jailbreak, misconfigured tool permissions)
- Tool access re-enabled only with additional authorization controls
- Principle of least privilege applied to all agent tool permissions
- No SIG-007 anomalies for 48 hours after re-enabling tool access
- Lesson learned complete

---

### LESSON LEARNED TEMPLATE

1. **What did the agent do that it should not have done?** (Specific action, specific target)
2. **Was there a user intent that could have led to this action through a legitimate path?** (Determines if this is a logic bug vs. an attack)
3. **What minimum permission set does this agent need to perform its intended function?** (Use this incident to justify access reduction)
4. **Was human-in-the-loop approval available for this action? Should it be mandatory going forward?**
5. **If an attacker had full control of this agent's tool calls, what is the worst thing they could accomplish in your environment?** (Threat model the agent — this should inform your containment architecture)

---
---

## PLAYBOOK 5: Refusal Rate Drop
### Signal: SIG-009 | Severity: MEDIUM → HIGH (sustained)
### OWASP: LLM01 Prompt Injection (systematic)

---

### TRIGGER

This playbook activates when:

- The model's refusal rate on a monitored request category drops more than 30% below the established 7-day baseline within a 24-hour window
- The model stops refusing requests that it was reliably refusing in the prior week
- SIG-009 fires after Monitor detects that BLOCK events are decreasing while the underlying prompt patterns have not changed (traffic composition is consistent, refusals are dropping)
- Manual review of recent sessions shows the model complying with requests it previously refused

**Why this is subtle:** A refusal rate drop is not a single attack. It is a statistical signal that something has changed in how your model responds to certain content. It could be:
- Gradual system prompt manipulation (attacker is slowly normalizing the model across many sessions)
- Model update that changed behavior (your LLM provider deployed a new version)
- Legitimate prompt engineering improvement that reduced over-refusal (good thing)
- Systematic jailbreak campaign that has been partially successful

You cannot tell which without investigation.

---

### SEVERITY ASSESSMENT

| Cause | Severity |
|-------|----------|
| LLM provider model update changed default behavior | LOW — operational, not security |
| Your team made a system prompt change that reduced over-refusal | LOW — expected, document it |
| Users have discovered a reliable soft manipulation technique | MEDIUM — address it |
| Coordinated multi-session jailbreak campaign that is working | HIGH — incident |
| Compromised system prompt (attacker changed your instructions) | CRITICAL — full incident |

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Check for recent system prompt changes.** Did your team modify the AI system's configuration in the last 24–72 hours? If yes, correlate the change with the timing of the refusal rate drop. This is the most common benign explanation.

2. **Check for LLM provider model updates.** Has your API provider deployed a new model version? Some providers automatically roll forward to newer versions. Model behavior changes are a legitimate cause of refusal rate shifts.

3. **Pull a sample of sessions where the model *should* have refused but did not.** Identify at least 5 specific examples of a request that was refused last week and is not being refused this week.

4. **Notify the AI system owner.** This is not a 3am page but it is a same-day notification.

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Establish the timeline.**

When did the refusal rate start dropping? Use Monitor's historical chart. Did it drop suddenly (possible single cause: model update, system prompt change, or a specific campaign starting) or gradually (suggests iterative manipulation)?

**Step 2 — Correlate with known changes.**

Build a timeline:
- When did the drop start?
- Were there any system prompt changes in the preceding 72 hours?
- Were there any model version changes?
- Were there any unusual traffic spikes or new user accounts in the same window?

**Step 3 — Analyze the sessions where refusals stopped.**

For each session where the model complied with a previously-refused request:
- Was there a prior conversation turn that could have shifted the model's context? (Iterative manipulation)
- Is the same user account appearing repeatedly in these sessions? (Individual exploiting a technique)
- Are the requests themselves different in structure from the original refused requests? (Jailbreak technique evolution)
- Did any session contain a jailbreak payload earlier in the conversation? (SIG-005 may have fired before SIG-009 became detectable)

**Step 4 — Test current refusal behavior.**

In a sandboxed session, send 10 requests that your model should refuse. Document which ones it refuses and which it complies with. Compare to baseline. This confirms whether the change is real and quantifies the gap.

**Step 5 — Inspect current system prompt.**

Pull the current system prompt and compare it to the version in use 7 days ago. If there are differences you did not authorize, your system prompt has been modified — escalate immediately to CRITICAL incident.

---

### ESCALATION CRITERIA

Escalate to HIGH severity:

- System prompt has been modified without authorization
- The drop is correlated with a specific set of user accounts using consistent manipulation techniques
- Refusals have dropped in a safety-critical category (the model is no longer refusing to produce harmful content it was previously blocking)
- No benign explanation (model update, intentional system prompt change) can account for the drop

---

### CONTAINMENT OPTIONS

**Option 1 — Restore the previous system prompt**
If unauthorized changes were made, roll back immediately. Diff the current prompt against your version-controlled backup.

**Option 2 — Reinforce refusal instructions**
Add explicit, unambiguous refusal instructions for the affected categories directly into the system prompt. Move these instructions to the top of the prompt — position matters.

**Option 3 — Pin the model version**
If your provider is automatically updating your model version, pin to a specific version to restore consistent behavior while you evaluate the new model.

**Option 4 — Add output classification**
Deploy a secondary classifier (rule-based or model-based) that reviews model output for policy compliance before delivery. This catches compliant outputs that slipped through.

**Option 5 — Session-level context reset**
If iterative manipulation is occurring (attacker builds up context across turns to normalize the model), limit session memory length or add a context reset mechanism that re-anchors the model to its system prompt periodically within long sessions.

---

### EVIDENCE COLLECTION

- Refusal rate trend data from Monitor for the past 14 days
- System prompt version history (current and previous)
- Sample sessions (minimum 10) showing the changed behavior
- LLM provider changelog for any model updates in the relevant window
- Traffic analytics showing any unusual patterns

---

### COMMUNICATION

**Internal:**
- AI system owner: refusal rate is down, here is the delta, here are sample sessions
- Security team: potential systematic manipulation, investigation in progress

**Note:** This is not an external communication event unless the refusal rate drop led to actual harmful output being delivered to users.

---

### RESOLUTION CRITERIA

- Root cause identified (benign or adversarial)
- Refusal rate returned to baseline for 48 hours
- System prompt reviewed and hardened if adversarial cause was found
- Monitor baseline recalibrated if the change was intentional (new system prompt, model version pin)
- Lesson learned complete if adversarial cause was confirmed

---

### LESSON LEARNED TEMPLATE

1. **What category of requests did the model stop refusing?** (Be specific — broad refusal drops are often just model updates, but drops in a specific category are suspicious)
2. **Was the cause adversarial manipulation, operational change, or model drift?** (This determines what to fix)
3. **How long did the model operate with reduced refusals before detection?** (This is your detection latency — a key Monitor KPI)
4. **What prompt hardening technique most directly addresses the manipulation method used?**
5. **Should this category of refusal have a higher confidence threshold that triggers real-time BLOCK rather than just WARN?** (Use this to tune Monitor's detection sensitivity)

---
---

## PLAYBOOK 6: SDK Offline / Monitoring Blind Spot
### Signal: SIG-010 | Severity: HIGH
### Classification: Operational / Monitoring Integrity

---

### TRIGGER

This playbook activates when:

- Ghost99RT heartbeat to AISeal Monitor goes silent for more than 5 minutes
- SIG-010 fires — Monitor has stopped receiving telemetry from one or more monitored AI systems
- Monitor dashboard shows a monitored system transitioning from LIVE to OFFLINE status
- Latency on Ghost99RT health check endpoint exceeds 30 seconds (timeout)
- AISeal Monitor alert: "Telemetry gap detected — [system name] last seen [timestamp]"

---

### SEVERITY ASSESSMENT

**What this means:**

When Ghost99RT goes offline, your AI system is still running — it is just unmonitored. Every minute of blind spot is a minute during which attacks could occur, succeed, and leave no trace in Monitor.

This is not a threat in itself. It is a gap in your defenses. The severity is a function of:
- How long the gap lasts
- How active your AI system's traffic is during the gap
- Whether the gap coincides with any other anomalous signals

A 3-minute gap at 3am on a low-traffic system is a low-urgency operational issue. A 30-minute gap during peak hours on an agent with tool access is HIGH severity.

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Note the exact start time of the gap.** This timestamp is critical — you need to know exactly which traffic occurred outside monitoring coverage.

2. **Verify whether your AI system is still serving traffic.** A monitoring gap is worse when the underlying system is actively handling requests. Check your application's health endpoint, load balancer logs, or user activity logs to confirm whether traffic was flowing during the gap.

3. **Attempt to restore Ghost99RT connectivity.**

   Common causes and immediate fixes:
   - Network connectivity issue: check if the host running Ghost99RT can reach the AISeal Monitor endpoint
   - Ghost99RT process crash: check process status and restart
   - API key or authentication expiry: verify credentials are current
   - Host resource exhaustion (CPU/memory): check system health

4. **Do not assume the gap was malicious.** Infrastructure glitches are the most common cause. But treat the gap as a potential cover for an attack until you can verify traffic during the gap was clean.

5. **Notify the AI system owner and engineering team.**

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Determine the cause of the offline event.**

Collect:
- Ghost99RT process logs from the host
- Host system logs (dmesg, syslog, or equivalent) for the gap period
- Network connectivity tests between the Ghost99RT host and AISeal Monitor endpoints
- Any deployment or configuration changes made near the time of the gap

**Step 2 — Reconstruct traffic during the gap.**

Pull your AI system's independent logs (application logs, API gateway logs, load balancer logs) for the exact window of the monitoring gap. How many requests were processed? What were the rough patterns?

This is your best-effort blind spot reconstruction. It won't have Ghost99RT's classification, but it tells you:
- Traffic volume during the gap (baseline vs. anomalous)
- Any obviously suspicious patterns you can catch manually
- User accounts or IP addresses active during the gap

**Step 3 — Check for any post-gap anomalies.**

Once monitoring is restored, watch the first 30 minutes of Ghost99RT telemetry closely. If an attack was in progress during the blind spot, it may still be in progress when monitoring resumes. Look for:
- Elevated BLOCK rates immediately after restoration
- SIG-002, SIG-005, or SIG-007 firing shortly after monitoring resumes
- Tool calls that reference actions or data from the gap period

**Step 4 — Assess if the outage was induced.**

In rare cases, sophisticated attackers intentionally take monitoring infrastructure offline before an attack. Look for:
- Any unusual API calls to the Ghost99RT host or AISeal API before the gap
- Correlation between the gap and any high-traffic anomalies in your application logs
- If the gap occurred immediately before or after a suspicious session

---

### ESCALATION CRITERIA

Escalate to HIGH priority:

- Gap exceeds 30 minutes with active AI system traffic
- Cause cannot be determined (no obvious infrastructure reason for the outage)
- Post-restoration telemetry shows immediate BLOCK or CRITICAL signals (suggests attack during the gap)
- Multiple Ghost99RT instances go offline simultaneously (possible coordinated attack on monitoring infrastructure)

---

### CONTAINMENT OPTIONS

**Option 1 — Restore monitoring immediately**
Priority one. Until monitoring is restored, all other options are secondary.

**Option 2 — Reduce AI system attack surface during the gap**
If the gap is prolonged and the AI system is actively handling sensitive traffic: consider temporarily disabling tool access or putting the AI system in read-only mode until monitoring is restored.

**Option 3 — Manual log review**
For gaps under 60 minutes: do a manual review of your application's native logs. It is labor-intensive but bridges the gap.

**Option 4 — Enable redundant monitoring**
If this gap reveals a single point of failure in your Ghost99RT deployment, design for redundancy: multiple Ghost99RT instances, health check alerting, automatic restart on crash.

---

### EVIDENCE COLLECTION

- Ghost99RT process logs from the gap period
- Host system logs for the gap period
- Application/API gateway logs for the gap period
- Timeline of the gap: start, end, duration
- Root cause determination

---

### COMMUNICATION

**Internal:**
- AI system owner: monitoring was offline from [time] to [time], traffic during gap was [volume], manual review status
- Security team: duration of gap, whether post-gap telemetry shows any anomalies

**If gap was prolonged and you cannot rule out an attack during the gap:**
Treat the gap period as potentially compromised and apply Playbooks 1–4 manually to your best-effort log reconstruction.

---

### RESOLUTION CRITERIA

- Ghost99RT fully online and telemetry confirmed
- Root cause of outage identified and documented
- Gap period traffic reviewed (manually if necessary)
- No anomalous signals in first 2 hours post-restoration
- Remediation steps taken to prevent recurrence
- Monitoring architecture reviewed for single-point-of-failure risks

---

### LESSON LEARNED TEMPLATE

1. **What caused the monitoring gap?** (Infrastructure failure, misconfiguration, resource exhaustion, credential expiry)
2. **What was the volume and nature of AI system traffic during the gap?** (This quantifies your exposure)
3. **Was there any evidence of attack during or immediately after the gap?**
4. **What architectural change would have prevented this gap or detected it faster?** (Redundant monitoring, health check alerting, automated restart)
5. **What is your current mean time to detection for a monitoring outage?** (This is a key operational metric — you should know about a Ghost99RT outage in under 5 minutes)

---
---

## PLAYBOOK 7: AISeal Cert Under Review
### Signal: SIG-011 | Severity: MEDIUM
### Classification: Certification Health / Compliance

---

### TRIGGER

This playbook activates when:

- AISeal Cert health score drops more than 10 points from the last certification assessment
- One or more previously-passing certification checks regresses to failing
- A new OWASP LLM Top 10 or MITRE ATLAS control is added to the AISeal Cert framework and your AI system has not been assessed against it
- AISeal Cert status transitions from CERTIFIED to UNDER REVIEW
- Certification renewal window opens (90 days before expiry) and a new assessment has not been initiated

---

### SEVERITY ASSESSMENT

**What this means:**

AISeal Cert is your AI system's security posture attestation. A score drop or status change to UNDER REVIEW means one of:

1. Your AI system's actual security posture has degraded (you changed something and it broke a control)
2. The certification framework has been updated and your system hasn't been re-assessed (framework drift)
3. Monitor data from the past certification period shows risk signals that affect the certification calculation
4. Your certification is approaching expiry

None of these are an emergency. They are all on a clock. A system operating UNDER REVIEW has reduced customer trust signals and may affect enterprise sales or compliance reviews.

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Pull the AISeal Cert dashboard and identify specifically which controls regressed or are newly required.** Do not treat "score dropped" as the problem — identify the specific control failures.

2. **Determine if the drop corresponds to a recent change in your AI system.** System prompt changes, model upgrades, new feature deployments, and tool integrations all affect certification score. Did you ship anything recently?

3. **Notify the AI system owner and compliance/security lead.** This is a business and compliance notification, not an emergency.

4. **Check the certification expiry date.** If expiry is within 30 days, escalate urgency.

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Identify the regressed controls.**

In AISeal Cert, pull the control-by-control breakdown. For each control that changed from PASS to FAIL:
- What is the control testing for?
- What changed in your system that would cause this regression?
- Is this a configuration change, a code change, or a policy change?

**Step 2 — Correlate with Monitor data.**

AISeal Cert factors in runtime Monitor data. Pull the last 30 days of Monitor signals. Are there recurring SIG-002, SIG-005, or SIG-007 alerts that are now dragging down the cert score? If yes, the certification score is accurately reflecting real security posture gaps — address those first.

**Step 3 — Assess the remediation path for each failed control.**

For each failed control, document:
- What is required to pass? (Technical configuration, policy update, architectural change)
- What is the effort level? (Hours, days, or weeks)
- Is there a compensating control that could be accepted in lieu?

**Step 4 — Build a remediation timeline.**

AISeal Cert scores are recalculated on each assessment scan. You can improve your score by fixing controls and triggering a new scan. Build a timeline for each control fix and target the next scan date.

---

### ESCALATION CRITERIA

Escalate urgency (not a security incident, but a business priority):

- Certification expiry within 30 days and remediation is not complete
- A customer or prospect has requested your current certification status and score
- Regulatory audit is scheduled and certification status is relevant to the audit
- Score dropped below a contractually committed threshold (if applicable)

---

### CONTAINMENT OPTIONS

**This playbook does not involve system containment.** The AI system continues operating normally. Actions are remediation-focused:

**Option 1 — Address the highest-weight failing controls first**
Not all controls have equal weight in the AISeal Cert scoring model. Prioritize controls that have the highest impact on your score.

**Option 2 — Request a provisional certification extension**
If you are actively remediating and need to maintain certification status during the remediation window, contact AISeal to request a provisional status extension with a committed remediation date.

**Option 3 — Initiate a new TrustScan immediately**
A fresh TrustScan run documents your current security posture and may surface additional issues before the full certification assessment. Run this before investing in remediation to get a complete picture.

**Option 4 — Update certification documentation**
Some certification controls are policy and documentation controls, not purely technical. Review whether any regressions can be resolved by updating your AI system's security documentation, usage policies, or incident response procedures.

---

### EVIDENCE COLLECTION

- Screenshot of the certification dashboard showing current score and control breakdown
- Diff of any AI system changes deployed since the last passing assessment
- Monitor signal summary for the last 30 days (fed into certification calculation)
- Remediation plan with control-by-control commitments

---

### COMMUNICATION

**Internal:**
- AI system owner and engineering lead: which controls regressed, what changes are needed
- Compliance/legal: certification status, expiry date, any customer commitments affected

**External (to customers, if required):**
If a customer has relied on your AISeal Cert status in a vendor assessment or contract, notify them proactively that a review is in progress and provide an expected restoration date. Proactive disclosure is always better than being discovered.

---

### RESOLUTION CRITERIA

- All failed controls remediated and verified
- New assessment scan confirms score has recovered
- Certification status returns to CERTIFIED
- Remediation steps documented in the AI system's security change log
- If framework expanded: new controls are tested and passing
- Lesson learned complete if the regression was caused by a change management failure

---

### LESSON LEARNED TEMPLATE

1. **Which specific change or event caused the certification regression?** (Identify the root cause — system change, Monitor data accumulation, or framework update)
2. **Was there a change management process that should have flagged this?** (Did someone deploy a system prompt change without running a TrustScan first?)
3. **How long between the regression-causing change and detection?** (Shorter is better — daily certification health monitoring is the goal)
4. **What process change ensures future deployments are evaluated against certification controls before going to production?**
5. **Is there a failing control that should trigger a security review before any system change is allowed to ship?** (Gate high-weight certification controls into your CI/CD pipeline)

---
---

## PLAYBOOK 8: Baseline Staleness Alert
### Signal: SIG-012 | Severity: LOW
### Classification: Operational / Monitor Hygiene

---

### TRIGGER

This playbook activates when:

- AISeal Monitor has not received a baseline update in more than 30 days
- The behavioral baseline that Monitor uses to detect anomalies was established more than 60 days ago without review
- A significant operational change has occurred (new use case, new user population, new system prompt, new model version) and Monitor has not been informed to recalibrate
- Monitor's anomaly detection false positive rate has increased more than 20% over the past 7 days (a leading indicator of stale baseline)

---

### SEVERITY ASSESSMENT

**What this means:**

AISeal Monitor detects anomalies by comparing current behavior to a baseline of normal behavior. If the baseline is stale, Monitor's detection quality degrades:

- **False positives increase**: Monitor flags legitimate behavior as suspicious because it looks different from the outdated baseline
- **False negatives increase**: Actual attacks look "normal" relative to a baseline that no longer reflects your system's actual behavior profile
- **Alert fatigue sets in**: Operators start ignoring alerts because they're wrong too often

This is a hygiene issue, not an emergency. But it silently degrades your security posture over time.

---

### IMMEDIATE ACTIONS (0–15 minutes)

1. **Acknowledge the alert.** SIG-012 is low severity but not ignorable.

2. **Identify what has changed since the last baseline calibration.** Common changes requiring recalibration:
   - New system prompt deployed
   - Model version updated
   - New use case or feature added to the AI system
   - Significant change in user population or traffic volume
   - New tool integrations added

3. **Assess current false positive rate.** Pull the last 7 days of Monitor alerts and review a sample. How many WARN alerts, when investigated, turned out to be legitimate behavior? If the answer is "most of them," your baseline is stale.

---

### INVESTIGATION STEPS (15 minutes – 2 hours)

**Step 1 — Document what has changed.**

Build a delta log: what is different about your AI system today versus when the baseline was last set? This includes technical changes (model, prompt, tools) and operational changes (use cases, user types, traffic patterns).

**Step 2 — Assess the impact on each signal type.**

For each Monitor signal category (SIG-001 through SIG-009), ask: "Has the baseline-setting change affected what normal behavior looks like for this signal?" 
For example: a new customer service use case might legitimately increase token output volume, making SIG-001 (Anomalous Token Volume) much noisier.

**Step 3 — Initiate a recalibration window.**

AISeal Monitor supports a supervised recalibration mode where you validate a sample of traffic as normal, updating the baseline. Work with your AISeal administrator to schedule a 48–72 hour recalibration window.

**Step 4 — Review detection thresholds.**

During recalibration, review each signal's detection threshold. Thresholds set for a prior system configuration may be too sensitive or not sensitive enough for the current deployment.

---

### ESCALATION CRITERIA

**No escalation criteria for SIG-012.** This is always an operational issue.

If you discover during baseline review that your current detection thresholds are so miscalibrated that they would have missed a real attack, document that finding and treat it as a security posture gap requiring prompt attention — but that is a process issue, not an active incident.

---

### CONTAINMENT OPTIONS

Not applicable. No containment is needed for baseline staleness. The action is recalibration.

**Recalibration steps:**

1. Export your current baseline configuration before changing it
2. Schedule a 48-hour supervised collection window during representative traffic
3. Review the collected sample (spot-check 50+ sessions) to confirm it represents legitimate use
4. Approve the new baseline
5. Verify that false positive rate returns to target levels within 24 hours of new baseline activation
6. Archive the old baseline configuration with a timestamp

---

### EVIDENCE COLLECTION

- Current baseline configuration (export before recalibration)
- List of system changes since last baseline
- False positive rate data for the last 30 days
- New baseline configuration post-recalibration

---

### COMMUNICATION

**Internal:**
- AI system owner: baseline is being recalibrated, expect brief changes in alert volume during the recalibration window
- Security team: alert quality may temporarily change during recalibration window, treat this as a planned maintenance event

---

### RESOLUTION CRITERIA

- New baseline established and validated
- False positive rate at target level (typically under 5% of WARN alerts on review)
- SIG-012 clear for 14 days
- Baseline review scheduled on calendar for 30 days out

---

### LESSON LEARNED TEMPLATE

1. **What change triggered the baseline staleness?** (Understand the root cause — was this an unplanned change that should have triggered a recalibration?)
2. **How long was Monitor operating on a stale baseline?** (Measure the detection quality gap)
3. **What process ensures that future system changes trigger a baseline recalibration?** (Build this into change management)
4. **What is the target recalibration cadence for this AI system?** (High-change systems need more frequent calibration than stable ones)
5. **Did the stale baseline coincide with any incidents that might have been harder to detect?** (Review incident log for the staleness period)

---
---

## MONITOR RUNBOOK: Configuration and Maintenance
### AISeal Monitor Operations Guide

---

### Initial Deployment

**Prerequisites:**
- Ghost99RT agent installed on the host running your AI system (or as a sidecar in your deployment architecture)
- AISeal API key provisioned and stored as `AISEAL_API_KEY` environment variable
- Network path open from Ghost99RT host to `monitor.aiseal.ai` (outbound HTTPS/443)
- Baseline traffic collection window: allow 48 hours of representative traffic before activating anomaly detection

**Ghost99RT Deployment Modes:**

*Proxy mode (recommended):* Ghost99RT sits between your application and the LLM API. All traffic flows through it. Maximum visibility, small latency addition (~5ms average).

*Sidecar mode:* Ghost99RT runs alongside your application container, receiving traffic copies via log streaming. No latency impact, slightly reduced fidelity on tool call inspection.

*Passive mode:* Ghost99RT receives log stream exports. No real-time blocking capability. Suitable for read-only monitoring where BLOCK capability is not needed.

**Initial Configuration Checklist:**
- [ ] Ghost99RT process running and sending heartbeat
- [ ] AISeal Monitor dashboard showing LIVE status for monitored system
- [ ] All relevant signal types enabled for your deployment type
- [ ] Baseline collection window completed (48 hours minimum)
- [ ] Alert routing configured (email, Slack, PagerDuty, or webhook)
- [ ] Incident response contact list configured in Monitor settings
- [ ] Test alert sent and received by all configured channels

---

### Alert Tuning

**Adjusting signal sensitivity:**

Each signal has a confidence threshold (0.0–1.0). The default threshold is tuned for general enterprise deployments. Adjust for your context:

*Increase sensitivity (lower threshold)* when:
- Your AI system handles sensitive data (medical, financial, legal)
- Your AI system has tool access with write/send capabilities
- You have a dedicated security operations team to handle increased alert volume
- You are in a high-threat environment (financial institution, healthcare, government)

*Decrease sensitivity (raise threshold)* when:
- False positive rate is above 10% of reviewed WARN alerts
- Your AI system's use case legitimately produces patterns that resemble attack patterns (security training chatbots, red team tools)
- You are running in a development or staging environment

**Per-signal tuning guidelines:**

| Signal | Default Threshold | When to Lower | When to Raise |
|--------|------------------|---------------|---------------|
| SIG-002 (Prompt Injection) | 0.78 | Tool-use agents | Chatbots where injection attempts are rare |
| SIG-003 (Data Exfiltration) | 0.70 | Any system with PII access | Development systems with test data only |
| SIG-005 (Jailbreak Success) | 0.85 | Public-facing, anonymous users | Authenticated enterprise users |
| SIG-007 (Tool Call Anomaly) | 0.75 | Agents with destructive tool access | Agents with read-only tool access |
| SIG-009 (Refusal Rate Drop) | 30% delta | Stable, well-defined AI systems | Rapidly evolving applications |

---

### False Positive Handling

**What to do with a false positive:**

1. Document it: signal ID, session ID, why it was a false positive, what legitimate behavior triggered it.
2. Do NOT adjust thresholds based on a single false positive. Adjust only when you see a pattern.
3. Tag the session as a false positive in Monitor. This feeds the detection improvement model.
4. If the same false positive pattern recurs 5+ times in a week, submit a pattern report to AISeal support for rule refinement.

**Common false positive sources:**

| Signal | Common False Positive Cause | Resolution |
|--------|----------------------------|------------|
| SIG-002 | Security awareness training content, red team testing | Allowlist known testing session sources |
| SIG-003 | Legitimate large data summaries (quarterly reports) | Tune output size threshold, tag expected large-output use cases |
| SIG-007 | Expected tool call patterns being flagged as anomalous | Recalibrate baseline after new tool integrations |
| SIG-009 | System prompt improvement that legitimately reduced over-refusal | Recalibrate baseline, document the intentional change |

**Allowlisting:**
Monitor supports session-source allowlisting (by IP, user ID, or API key). Use this for known red team sources, internal testing, and development environments. Do not allowlist production user sources.

---

### Baseline Management

**Recalibration triggers (any of these should prompt a recalibration):**
- New system prompt deployed
- Model version change
- New tools or capabilities added to the agent
- Significant change in traffic volume (>50% increase/decrease)
- New user population or use case
- SIG-012 fires (Monitor will prompt you automatically)

**Recalibration procedure:**
1. Export current baseline: Monitor → Settings → Baseline → Export
2. Enter recalibration mode: Monitor → Settings → Baseline → Recalibrate
3. Allow 48 hours of supervised traffic collection
4. Review collection sample: spot-check minimum 50 sessions across all time periods
5. Approve baseline: confirm the sample represents legitimate, expected behavior
6. Monitor false positive rate for 24 hours post-activation
7. Archive old baseline with timestamp and reason for change

**Baseline retention:** Keep the last 3 baselines archived. A baseline is part of your security audit trail — if an incident occurred while a specific baseline was active, you need to be able to reconstruct the detection environment.

---

### Alert Routing and Escalation Configuration

**Alert routing rules:**

Configure routing in Monitor → Settings → Alerts. Recommended configuration:

| Severity | Channel | Escalation Timer |
|----------|---------|------------------|
| CRITICAL | PagerDuty / on-call phone | 5 minutes unacknowledged → escalate |
| HIGH | Slack #security-alerts + email | 15 minutes unacknowledged → escalate |
| MEDIUM | Email + Slack | 2 hours unacknowledged → notify manager |
| LOW | Email only | 24 hours unacknowledged → reminder |

**On-call rotation:**
Monitor should have a minimum of two contacts in the on-call rotation. A single-person on-call for AI security means a sick day creates a monitoring blind spot.

**Integration setup:**
- Slack: Monitor → Settings → Integrations → Slack → install app, select channel
- PagerDuty: Monitor → Settings → Integrations → PagerDuty → enter service key
- Email: Monitor → Settings → Alerts → Email → add recipients per severity level
- Webhook: Monitor → Settings → Integrations → Webhook → configure endpoint for custom SIEM/SOAR integration

---

### Monthly Maintenance Tasks

**First week of each month:**
- Review false positive rate for the prior month. If above 5%, schedule threshold tuning.
- Verify all alert routing channels are functional (send a test alert).
- Review baseline age. If over 30 days since last recalibration with no system changes, consider a proactive recalibration.
- Check Ghost99RT version. If a new version is available, plan upgrade.

**Quarterly:**
- Full baseline recalibration regardless of system changes.
- Review detection coverage: are all relevant signal types enabled for your current AI system's capabilities?
- Audit the allowlist: remove any entries that are no longer needed.
- Test your incident response procedures: run a tabletop exercise with a real alert scenario.
- Review and update the on-call rotation and escalation contacts.

---
---

## SECURITY POSTURE REVIEW: Monthly CISO Template
### AISeal Monitor — Executive Security Review

**Review Period:** [Month/Year]  
**AI Systems Under Review:** [List of monitored systems]  
**Prepared By:** [Name/Role]  
**Reviewed By:** [CISO Name]

---

### Section 1 — Threat Landscape (5 minutes)

**Q1: What was the total threat signal volume this month?**

| Signal | Count | vs. Last Month | Trend |
|--------|-------|---------------|-------|
| SIG-002 Prompt Injection | | | ↑↓→ |
| SIG-003 Data Exfiltration | | | ↑↓→ |
| SIG-005 Jailbreak Attempts | | | ↑↓→ |
| SIG-007 Tool Call Anomalies | | | ↑↓→ |
| SIG-009 Refusal Rate Drop | | | ↑↓→ |
| All Signals (total) | | | ↑↓→ |

**Q2: What was the confirmed incident count?**
- Incidents declared: ___
- False positives confirmed: ___
- Detection precision rate: ___% (incidents / total alerts)

**Q3: What was the highest-severity confirmed incident this month?**
[One sentence: what happened, when, what was the outcome]

---

### Section 2 — Attack Pattern Analysis (10 minutes)

**Q4: What were the top 3 attack techniques observed this month?**

1. [Technique — e.g., indirect prompt injection via document upload]
2. [Technique]
3. [Technique]

**Q5: Is the attack volume on any signal type increasing over the trailing 90-day trend?**
[Yes/No + which signals if yes]

**Q6: Were any new attack techniques observed that were not in the prior month's threat model?**
[Yes/No + description if yes]

**Q7: Are attacks concentrated on specific AI systems, use cases, or user populations?**
[Pattern description or "No concentration observed"]

---

### Section 3 — AI System Security Posture (10 minutes)

**Q8: What is the current AISeal TrustScore for each monitored system?**

| AI System | TrustScore | Change from Last Month | Cert Status |
|-----------|------------|----------------------|-------------|
| [System 1] | /100 | | CERTIFIED / UNDER REVIEW |
| [System 2] | /100 | | |

**Q9: Are any certification controls in a failing state?**
[List controls if yes, with remediation status and owner]

**Q10: What is the current tool access posture across all monitored AI agents?**
- Agents with write/destructive tool access: ___
- Agents with external communication tool access (email, webhooks): ___
- Agents operating under principle of least privilege: ___ of ___

**Q11: When was the last baseline recalibration for each monitored system?**

| AI System | Last Calibration | Days Since | Status |
|-----------|-----------------|------------|--------|
| [System 1] | | | Current / Stale |

---

### Section 4 — Operational Metrics (5 minutes)

**Q12: What was the average time from alert to acknowledgment this month?**
- CRITICAL alerts: ___ minutes (target: <5 min)
- HIGH alerts: ___ minutes (target: <15 min)
- MEDIUM alerts: ___ minutes (target: <2 hours)

**Q13: What was the total monitoring uptime (Ghost99RT availability)?**
- Uptime: ___%
- Number of monitoring gaps: ___
- Longest single gap: ___ minutes

**Q14: What is the current false positive rate?**
- WARN alerts reviewed: ___
- WARN alerts confirmed false positive: ___
- False positive rate: ___%  (target: <5%)

---

### Section 5 — Remediation Status (10 minutes)

**Q15: What incidents from last month remain open or in remediation?**

| Incident | Date | Status | Owner | Expected Close |
|----------|------|--------|-------|---------------|
| | | | | |

**Q16: What security improvements were shipped to AI systems this month?**
[List: system prompt hardening, access control changes, detection rule updates, architecture changes]

**Q17: What improvements are planned for next month?**
[List with owners and target dates]

---

### Section 6 — Risk Assessment (5 minutes)

**Q18: What is the current top AI security risk for this organization?**
[One to three sentences — be specific about what could happen and to whom]

**Q19: What is the one action that would most reduce AI security risk in the next 30 days?**
[Specific, actionable, owned by a named person]

**Q20: Are there any AI systems in the organization that are not currently monitored by AISeal?**
[Yes/No — list any unmonitored systems. These are your blind spots.]

---

### Section 7 — Board/Executive Summary (2 minutes)

*Complete this section last. Maximum 5 sentences. No jargon.*

This month, [AI system name(s)] processed [volume] requests and AISeal Monitor detected [count] security events. [Count] were confirmed incidents requiring response. The most significant incident was [one sentence description]. Our AI systems' TrustScores are [status], and certification is [current]. The primary risk requiring attention next month is [one sentence].

---
---

## AI INCIDENT REPORT
### Standard Format — LLM Security Incident Documentation

---

**INCIDENT REPORT**
**Classification:** [CONFIDENTIAL / INTERNAL / PUBLIC — select one]  
**Report Status:** [DRAFT / FINAL]  
**Report Date:** [Date]  
**Report Author:** [Name, Role]

---

### Header

| Field | Value |
|-------|-------|
| Incident ID | [INC-YYYY-NNN] |
| Incident Title | [Brief descriptive title — e.g., "Prompt Injection Campaign Targeting Customer Support Agent"] |
| AI System Affected | [System name and environment — e.g., "Customer Support Chatbot — Production"] |
| Detection Source | AISeal Monitor — Signal [SIG-XXX] |
| Date/Time Detected | [YYYY-MM-DD HH:MM UTC] |
| Date/Time Resolved | [YYYY-MM-DD HH:MM UTC or ONGOING] |
| Total Duration | [Hours and minutes from detection to resolution] |
| Severity | [CRITICAL / HIGH / MEDIUM / LOW] |
| Incident Status | [INVESTIGATING / CONTAINED / RESOLVED / CLOSED] |

---

### Executive Summary

*Two to four sentences. What happened, what was the impact, what was done about it. Written for a non-technical reader.*

[Write here]

---

### Timeline

| Time (UTC) | Event |
|------------|-------|
| [HH:MM] | AISeal Monitor fired [SIG-XXX] alert — [brief description] |
| [HH:MM] | Alert acknowledged by [name/role] |
| [HH:MM] | [Next significant action or finding] |
| [HH:MM] | [First containment action taken] |
| [HH:MM] | [Investigation milestone] |
| [HH:MM] | [Root cause identified] |
| [HH:MM] | [Containment confirmed] |
| [HH:MM] | [Incident closed] |

---

### Technical Details

**Attack/Anomaly Type:** [Prompt injection / Data exfiltration / Jailbreak / Tool call anomaly / Refusal manipulation / Other]

**OWASP LLM Category:** [LLM01 / LLM02 / LLM04 / LLM05 / LLM06 / LLM07 / LLM10]

**MITRE ATLAS Technique (if applicable):** [Technique ID and name]

**Affected Sessions:** [Count of affected session IDs]

**Attack Vector:** [Direct user input / Indirect via retrieved content / Stored injection / Automated / Unknown]

**Technique Description:**
*Describe specifically what the attacker did or what behavior anomaly was detected. Include the payload or pattern if appropriate for the classification level of this document.*

[Write here]

**Model Behavior Under Attack:**
*Did the model comply with the attack? Was it blocked by Ghost99RT? Did it partially comply? Was there tool access involved?*

[Write here]

---

### Impact Assessment

**Data Exposure:**
- Was any data exposed that should not have been? [Yes / No / Unknown]
- If yes: Data category: ___ | Volume: ___ | Recipient: ___

**Action Exposure:**
- Did the AI system take any unauthorized actions (tool calls, external communications)? [Yes / No]
- If yes: Describe the action, target, and any reversibility status.

**Service Impact:**
- Was the AI system's availability or functionality affected? [Yes / No]
- If yes: Describe the impact and duration.

**Affected Users:**
- Number of users whose sessions were involved: ___
- Were any users exposed to harmful content or unauthorized disclosures? [Yes / No]

**Regulatory Exposure:**
- Does this incident involve regulated data categories? [Yes / No]
- If yes: Applicable regulation: ___ | Notification obligation: ___ | Legal reviewed: [Yes / No]

---

### Root Cause

*One to three sentences. What was the underlying reason this incident occurred?*

[Write here]

**Root Cause Category:** [Select one]
- [ ] Insufficient input validation / prompt hardening
- [ ] Overly permissive tool access
- [ ] Misconfigured or absent access controls on data sources
- [ ] Model behavior change (provider update)
- [ ] Attacker-controlled content in retrieval pipeline (indirect injection)
- [ ] Stale baseline degrading detection quality
- [ ] Monitoring gap (Ghost99RT offline during attack)
- [ ] Social engineering of AI system persona
- [ ] Credential or API key exposure
- [ ] Other: ___

---

### Containment Actions Taken

| Action | Time Taken | Taken By | Outcome |
|--------|-----------|----------|---------|
| [e.g., Suspended tool access] | [HH:MM] | [Name/Role] | [e.g., Tool calls halted within 2 minutes] |
| | | | |
| | | | |

---

### Remediation

**Immediate Fixes (completed during incident):**
- [List each fix with owner and completion timestamp]

**Short-term Fixes (within 7 days):**
- [List each fix with owner and target date]

**Long-term / Architectural Changes (30+ days):**
- [List each change with owner and target date]

---

### Evidence Inventory

| Evidence Item | Format | Location | Retention Until |
|---------------|--------|----------|----------------|
| Session transcripts | JSON export | [Path/system] | [Date] |
| Ghost99RT alert data | JSONL | [Path/system] | [Date] |
| Tool call logs | Log file | [Path/system] | [Date] |
| Application access logs | Log file | [Path/system] | [Date] |
| System prompt snapshots | Text file | [Path/system] | [Date] |
| Baseline configuration | Export | [Path/system] | [Date] |

**Minimum retention: 90 days.** For incidents involving regulated data: follow applicable regulatory retention requirements.

---

### Lessons Learned

**1. What detection worked well?**
[What signals, rules, or processes caught this incident]

**2. What detection missed or was slow?**
[Gaps in monitoring coverage, late alerts, false negative patterns]

**3. What containment worked well?**
[What actions were fast and effective]

**4. What containment was slow or ineffective?**
[What should change about the response process]

**5. What is the single most important change to make to prevent recurrence?**
[One specific, actionable, owned recommendation]

---

### Sign-offs

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Incident Commander | | | |
| AI System Owner | | | |
| Security Lead | | | |
| Legal / Privacy (if applicable) | | | |
| CISO (for CRITICAL incidents) | | | |

---

*This document is produced under the AISeal Monitor security operations framework. For questions about this incident report format, contact your AISeal customer success representative.*

---

*AISeal Monitor v1.0 | Ghost99RT Engine | aiseal.ai*
