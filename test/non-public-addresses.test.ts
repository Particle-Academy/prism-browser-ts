import { describe, expect, it } from 'vitest';
import { BrowserPolicy, BrowserRefused } from '../src/index.js';

/**
 * G-89 (prism-browser-ts#1). The policy promises to refuse a non-public address EVEN WHEN IT IS ALLOW-LISTED, and this
 * port's check knew only ::1 for IPv6: CGNAT (Alibaba Cloud's metadata endpoint), the NAT64 and 6to4 spellings of
 * 169.254.169.254, unique-local, link-local and IPv4-mapped loopback were all admitted. Each address below is
 * allow-listed by its NORMALISED hostname, so the only thing that can refuse it is the address check.
 */
function refusal(host: string): string {
  const url = `https://${host}/latest/meta-data`;
  const policy = new BrowserPolicy({ allowedHosts: [new URL(url).hostname] });
  try {
    policy.assertUrl(url);
    return 'no_refusal';
  } catch (error) {
    if (error instanceof BrowserRefused) return error.code;
    throw error;
  }
}

describe('non-public addresses are refused even when allow-listed', () => {
  it.each([
    '169.254.169.254', '127.0.0.1', '10.0.0.5', '172.16.0.1', '192.168.0.1', '0.1.2.3', '240.0.0.1',
    '100.100.100.200', '100.64.0.1', '192.0.0.170', '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1',
    '224.0.0.1', '[::1]', '[::]', '[fd00::1]', '[fe80::1]', '[::ffff:127.0.0.1]', '[::7f00:1]',
    '[64:ff9b::a9fe:a9fe]', '[64:ff9b::169.254.169.254]', '[64:ff9b::7f00:1]', '[64:ff9b:1::a9fe:a9fe]',
    '[2002:a9fe:a9fe::]', '[2002:a00:5::1]', '[2001:0:4136:e378:8000:63bf:3fff:fdd2]', '[2001:db8::1]',
    '[100::1]', '[fec0::1]', '[ff02::1]',
  ])('%s', (host) => {
    expect(refusal(host)).toBe('private_address_refused');
  });
});

describe('public addresses still navigate (the controls)', () => {
  it.each(['8.8.8.8', '[64:ff9b::808:808]', '[2002:808:808::1]', '[2606:4700:4700::1111]'])('%s', (host) => {
    expect(refusal(host)).toBe('no_refusal');
  });
});
