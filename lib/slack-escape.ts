// AISeal F12 fix — Slack mrkdwn escape helper.
//
// The /api/registry/apply route interpolates user-supplied fields (company_name,
// product_name, contact_name, email, description, how_heard) directly into
// Slack Block Kit mrkdwn blocks. Slack mrkdwn parses:
//   *bold* _italic_ ~strike~ `code` <http://url|text> <!channel> <!here>
//
// An attacker submitting `<!channel> URGENT vendor announcement` as a field
// can hijack the Slack notification (fake @channel ping) or insert spoofed
// links with `<https://fake.aiseal.ai|Click here to verify>`.
//
// The fix is conservative — escape every mrkdwn special character AND insert a
// zero-width space inside the two special sigils (`<!` and `<http`) so Slack's
// parser never recognizes them as opening tokens. The escape is opt-in (call
// site decides when to apply) so we don't accidentally break legitimate
// mrkdwn we generate ourselves elsewhere.

const ZWSP = "​";

/**
 * Escape Slack mrkdwn special characters in user-supplied strings.
 * Use on every field that originated from an untrusted source before
 * interpolating into a `{ type: "mrkdwn", text: ... }` block.
 */
export function escapeMrkdwn(s: string | undefined | null): string {
  if (s == null) return "";
  return String(s)
    // Format chars: escape with backslash. Slack respects \* etc.
    .replace(/[*_~`]/g, (c) => `\\${c}`)
    // Special sigils that open mention / link syntax. Insert ZWSP after the
    // angle bracket so Slack's parser sees `<​!` and treats it as
    // literal text. The displayed output is visually indistinguishable from
    // the original input.
    .replace(/<!/g, `<${ZWSP}!`)
    .replace(/<http/g, `<${ZWSP}http`)
    .replace(/<#/g, `<${ZWSP}#`)
    .replace(/<@/g, `<${ZWSP}@`);
}
