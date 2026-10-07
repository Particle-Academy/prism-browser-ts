# Prism Browser for TypeScript

A policy-bounded browser surface for agents. The TypeScript port of
[`particle-academy/prism-browser`](https://github.com/Particle-Academy/prism-browser).

Zero runtime dependencies. Node 22+.

```
npm install @particle-academy/prism-browser
```

## Usage

The package does not drive a browser. It wraps one you supply — Playwright,
Puppeteer, a remote service — behind a policy that decides what the agent is
allowed to ask for:

```ts
import { BrowserPolicy, GuardedBrowser } from '@particle-academy/prism-browser';

const policy = new BrowserPolicy({
  allowedHosts: ['docs.example.com'],
  allowedActions: ['click', 'fill'],
  maxObservationBytes: 200_000,
});

const browser = new GuardedBrowser(myEngine, policy);

await browser.navigate('https://docs.example.com/guide');
await browser.act({ kind: 'click', selector: '#next' });
```

Implement `BrowserEngine` for whatever actually holds the page — two methods,
`navigate(url)` and `act(action)`, each returning an `Observation`. A consumer
holding a `GuardedBrowser` cannot reach the engine through it, which is the
point. A refusal throws `BrowserRefused`, whose `code` names which rule stopped
it.

## What the policy is for

An agent that can navigate is an agent that can make requests from inside your
network, so the defaults refuse rather than permit:

| Default | Why |
|---|---|
| `allowedHosts` is required | There is no "any host" to fall back to. The host list is the whole control. |
| `requireHttps` is **on** | Downgrading is a decision, not a default. |
| `allowPrivateAddresses` is **off** | A browser pointed at `http://169.254.169.254/` reads cloud metadata; one pointed at `localhost` reaches every service on the host that assumed it was unreachable. Allowing them is spelled out explicitly rather than inferred from the host list. |
| `maxObservationBytes` caps what comes back | A page is attacker-influenced input on its way into a prompt. |

## The limit of the private-address check, stated plainly

**It matches the hostname as written, not the address the name resolves to.**
`localhost`, anything under `.localhost` or `.local`, `::1`, and literal IPv4 in
`127/8`, `10/8`, `0/8`, `192.168/16`, `172.16/12` and `169.254/16` are refused.
A DNS name that resolves to one of those addresses is **not** refused, because
nothing here resolves it.

So this is a guard against an agent asking for a private address, not a defence
against DNS rebinding or a hostname someone else controls pointing inward. If
your agent may be handed arbitrary hostnames, keep the allow-list narrow and
enforce egress in the network, where it can actually be enforced. The same is
true of the PHP reference and the Python port — all three agree here, which is
precisely why agreement is not evidence of correctness.

## Parity

The refusal codes and the order the checks run in are pinned against the PHP
reference and the Python port by prism-parity's browser corpus, so a URL refused
in one language is refused in the other three for the same stated reason.
