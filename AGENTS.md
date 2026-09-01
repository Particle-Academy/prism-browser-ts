# AGENTS.md — prism-browser-ts

The TypeScript port of
[`particle-academy/prism-browser`](https://github.com/Particle-Academy/prism-browser).
Read the shared agent guide in `prism-parity/docs/AGENTS.md` first: the
boundary, the satellite map, the rules that bind, and the review skills.

## Gates — run them on EXIT CODES

```sh
npm run typecheck
npm run build
npx vitest run
```

Never pipe a gate into `head`/`tail`/`grep` and read `$?` — that is the
FILTER's exit code, not the gate's. Redirect to a file, echo `$?`, then look.

## What this package holds

The policy that bounds where an agent may navigate and what it may do there,
and the guard that frames a page observation as untrusted DATA before it reaches
a model. The engine itself is an injected interface.

## The rule that binds every port here

**Faithful to the reference, or a DOCUMENTED divergence — never a quiet one.**
Where this port does something the reference does not, the reason is in the
code and in the envelope's port gaps register. A difference nobody wrote down
is drift, and drift is what this whole effort exists to prevent.
