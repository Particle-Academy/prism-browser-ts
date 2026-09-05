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
 * G-21 IS CLOSED AND EVERY ROW NOW AGREES. Three of them used to be recorded as
 * divergences: all three languages refused the same URLs — the security
 * behaviour was identical and every private address was blocked — but the
 * reference named it `private_network_refused` and exposed it as
 * `$refused->reason`, where this port has always said `private_address_refused`
 * on `.code`. The REFERENCE moved, because the check is per-address rather than
 * per-network. Nothing changed in this file's implementation, only what it is
 * allowed to expect of the reference.
 */
interface PolicyCase {
  id: string;
  title: string;
  policy: { allowed_hosts: string[]; require_https?: boolean; allowed_ports?: number[] };
  url: string;
  refusal: { php: string | null; ts: string | null; py: string | null };
  agrees: boolean;
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

const privateAddress = corpus.cases.filter(
  (entry) => entry.refusal.ts === 'private_address_refused',
);

describe('the cross-language URL-policy corpus', () => {
  it('is the whole suite, not a subset someone trimmed to green', () => {
    expect(corpus.cases).toHaveLength(12);
  });

  it.each(corpus.cases)('$id produces this language’s recorded code ($title)', (entry) => {
    expect(refusalOf(entry)).toBe(entry.refusal.ts);
  });

  it.each(corpus.cases)('$id agrees with the PHP reference ($title)', (entry) => {
    expect(refusalOf(entry)).toBe(entry.refusal.php);
  });

  it('records no divergence left to explain', () => {
    // The count is asserted rather than the absence, so that a row quietly
    // flipped back to `agrees: false` fails here instead of being skipped by
    // every `filter` above it.
    expect(corpus.cases.filter((entry) => !entry.agrees)).toEqual([]);
  });

  it('refuses EVERY private address in the corpus, on exactly the rows that claim to', () => {
    // The security claim, stated independently of the code comparison. The
    // comparisons above only check that this language produces the string the
    // corpus recorded; if a change turned one of these into an ALLOW, the
    // corpus would be regenerated to record the allow and they would all stay
    // green. This is what would go red.
    expect(privateAddress.map((entry) => entry.id)).toEqual(['url-0005', 'url-0006', 'url-0007']);

    for (const entry of privateAddress) {
      expect(refusalOf(entry)).toBe('private_address_refused');
    }
  });

  it('never answers to the reference’s retired name', () => {
    for (const entry of corpus.cases) {
      expect([entry.refusal.php, entry.refusal.ts, entry.refusal.py]).not.toContain(
        'private_network_refused',
      );
    }
  });

  it('agrees with Python on every row', () => {
    for (const entry of corpus.cases) expect(entry.refusal.ts).toBe(entry.refusal.py);
  });
});
