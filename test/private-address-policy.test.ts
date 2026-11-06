import { describe, expect, it } from 'vitest';
import { BrowserPolicy, BrowserRefused, GuardedBrowser, type BrowserPolicyOptions, type BrowserEngine } from '../src/index.js';

const targets = [
  {
    "url": "https://127.0.0.1/",
    "hosts": [
      "127.0.0.1"
    ]
  },
  {
    "url": "https://localhost/",
    "hosts": [
      "localhost"
    ]
  },
  {
    "url": "https://127.1/",
    "hosts": [
      "127.1",
      "127.0.0.1"
    ]
  },
  {
    "url": "https://2130706433/",
    "hosts": [
      "2130706433",
      "127.0.0.1"
    ]
  },
  {
    "url": "https://0x7f000001/",
    "hosts": [
      "0x7f000001",
      "127.0.0.1"
    ]
  },
  {
    "url": "https://0177.0.0.1/",
    "hosts": [
      "0177.0.0.1",
      "127.0.0.1"
    ]
  },
  {
    "url": "https://169.254.169.254/",
    "hosts": [
      "169.254.169.254"
    ]
  },
  {
    "url": "https://100.100.100.200/",
    "hosts": [
      "100.100.100.200"
    ]
  },
  {
    "url": "https://10.0.0.1/",
    "hosts": [
      "10.0.0.1"
    ]
  },
  {
    "url": "https://[::1]/",
    "hosts": [
      "[::1]",
      "::1"
    ]
  },
  {
    "url": "https://[64:ff9b::a9fe:a9fe]/",
    "hosts": [
      "[64:ff9b::a9fe:a9fe]",
      "64:ff9b::a9fe:a9fe"
    ]
  },
  {
    "url": "https://[2002:a9fe:a9fe::1]/",
    "hosts": [
      "[2002:a9fe:a9fe::1]",
      "2002:a9fe:a9fe::1"
    ]
  }
] as const;

describe('unconditional private-address policy', () => {
  it.each([true, false, null, undefined, 0, 1, 'false'])('rejects the retired constructor option (%s)', (value) => {
    const options = { allowedHosts: ['example.com'], allowPrivateAddresses: value } as unknown as BrowserPolicyOptions;
    expect(() => new BrowserPolicy(options)).toThrowError(TypeError);
  });

  it('rejects a non-enumerable retired option', () => {
    const options = Object.defineProperty({ allowedHosts: ['example.com'] }, 'allowPrivateAddresses', { value: undefined });
    expect(() => new BrowserPolicy(options)).toThrowError(TypeError);
  });

  for (const target of targets) {
    it.each([false, true])('refuses before the engine: '+target.url+' (legacy property=%s)', async (assignLegacy) => {
      const policy = new BrowserPolicy({ allowedHosts: target.hosts });
      if (assignLegacy) Object.assign(policy, { allowPrivateAddresses: true });
      const calls: string[] = [];
      const engine: BrowserEngine = {
        navigate: async (url) => { calls.push(url); return { origin: url, url, title: 'Fixture', content: {} }; },
        act: async () => { throw new Error('Unexpected action'); },
      };
      await expect(new GuardedBrowser(engine, policy).navigate(target.url)).rejects.toMatchObject({ code: 'private_address_refused' });
      expect(calls).toEqual([]);
    });
  }

  it.each(['https://8.8.8.8/', 'https://www.example.com/'])('still reaches a declared public target: %s', async (url) => {
    const calls: string[] = [];
    const engine: BrowserEngine = {
      navigate: async (target) => { calls.push(target); return { origin: target, url: target, title: 'Fixture', content: {} }; },
      act: async () => { throw new Error('Unexpected action'); },
    };
    await new GuardedBrowser(engine, new BrowserPolicy({ allowedHosts: ['8.8.8.8', '*.example.com'] })).navigate(url);
    expect(calls).toEqual([url]);
  });

  it('serializes only the five reference policy fields', () => {
    const policy = new BrowserPolicy({ allowedHosts: ['example.com'] });
    expect('allowPrivateAddresses' in policy).toBe(false);
    Object.assign(policy, { allowPrivateAddresses: true });
    expect(Object.keys(policy.toObject()).sort()).toEqual(['allowed_actions', 'allowed_hosts', 'allowed_ports', 'max_observation_bytes', 'require_https']);
    expect(() => policy.assertUrl('https://127.0.0.1/')).toThrowError(BrowserRefused);
  });
});
