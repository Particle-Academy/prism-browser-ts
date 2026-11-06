# Changelog

## 0.3.0

- BREAKING CHANGE: remove the `allowPrivateAddresses` constructor option and policy field. Supplying the retired option raises `TypeError`, including `false` or `undefined`. Remove it from configuration. Private destinations are always refused, and serialized policies contain the five PHP reference fields.
