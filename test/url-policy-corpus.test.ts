import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { BrowserPolicy, BrowserRefused, type BrowserRefusalCode } from '../src/index.js';

/**
 * The cross-language URL-policy corpus from `prism-parity`.
 *
 * A refusal CODE is the contract — a consumer switches on it to decide whether
 * to retry, widen an allow-list, or surface a hard stop. The message is not,
 * and the corpus deliberately does not pin it: three implementations word these
 * differently on purpose, and asserting the prose holds every language to a
 * translation.
 *
 * The rows that diverge are asserted as DIVERGENCES rather than skipped. All
 * three languages refuse the same URLs — the security behaviour is identical
 * and every private address is blocked — but the reference names it
 * `private_network_refused` and this port names it `private_address_refused`.
 * See G-21.
 */
interface PolicyCase {
  id: string;
  title: string;
  policy: { allowed_hosts: string[]; require_https?: boolean; allowed_ports?: number[] };
  url: string;
  refusal: { php: string | null; ts: string | null; py: string | null };
  agrees: boolean;
  divergence?: string;
  notes: string;
}

const corpus = JSON.parse(
  readFileSync(new URL('./fixtures/browser-url-policy.json', import.meta.url), 'utf8'),
) as { cases: PolicyCase[] };

const refusalOf = (entry: PolicyCase): BrowserRefusalCode | null => {
  const policy = new BrowserPolicy({
    allowedHosts: entry.policy.allowed_hosts,
    requireHttps: entry.policy.require_https ?? true,
    allowedPorts: entry.policy.allowed_ports ?? [443],
  });

  try {
    policy.assertUrl(entry.url);

    return null;
  } catch (error) {
    if (!(error instanceof BrowserRefused)) throw error;

    return error.code;
  }
};

const agreeing = corpus.cases.filter((entry) => entry.agrees);
const diverging = corpus.cases.filter((entry) => !entry.agrees);

describe('the cross-language URL-policy corpus', () => {
  it('is the whole suite, not a subset someone trimmed to green', () => {
    expect(corpus.cases).toHaveLength(12);
  });

  it.each(corpus.cases)('$id produces this language’s recorded code ($title)', (entry) => {
    expect(refusalOf(entry)).toBe(entry.refusal.ts);
  });

  it.each(agreeing)('$id agrees with the PHP reference ($title)', (entry) => {
    expect(refusalOf(entry)).toBe(entry.refusal.php);
  });

  it.each(diverging)('$id refuses like the reference but NAMES it differently ($title)', (entry) => {
    // Two assertions, and both matter. The behaviour is identical — every one
    // of these is refused in all three languages — and only the code differs.
    // Asserting the refusal happened is what keeps this a naming finding rather
    // than letting a real hole hide behind the word "divergence".
    expect(refusalOf(entry)).not.toBeNull();
    expect(refusalOf(entry)).not.toBe(entry.refusal.php);
  });

  it('diverges on exactly the three rows the manifest names', () => {
    expect(diverging.map((entry) => entry.id)).toEqual(['url-0005', 'url-0006', 'url-0007']);
  });

  it('refuses EVERY private address in the corpus, whatever it calls it', () => {
    // The security claim, stated independently of the naming argument. If a
    // future rename accidentally turned one of these into an allow, the
    // divergence tests above would still pass — they only compare codes.
    for (const entry of diverging) expect(refusalOf(entry)).not.toBeNull();
  });

  it('agrees with Python on every row', () => {
    for (const entry of corpus.cases) expect(entry.refusal.ts).toBe(entry.refusal.py);
  });
});
