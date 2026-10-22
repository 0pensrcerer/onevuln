const express = require('express');
const crypto = require('crypto');
const http = require('http');

const router = express.Router();

// A03:2021 Injection — Code Injection (CWE-94)
router.get('/calc', (req, res) => {
  res.json({ result: eval(req.query.expr) });
});

// A02:2021 Cryptographic Failures — weak hash for passwords (CWE-327)
router.get('/register', (req, res) => {
  res.json({ hash: crypto.createHash('md5').update(req.query.password).digest('hex') });
});

// A05:2021 Security Misconfiguration — debug endpoint leaks environment (CWE-215)
router.get('/debug', (req, res) => res.json(process.env));

// A07:2021 Identification and Authentication Failures — hardcoded credential (CWE-798)
router.get('/admin', (req, res) => {
  if (req.query.password === 'admin123') return res.json({ secret: 'top-secret-data' });
  res.sendStatus(403);
});

// A10:2021 Server-Side Request Forgery (CWE-918)
router.get('/fetch', (req, res) => {
  http.get(req.query.url, (r) => r.pipe(res));
});

module.exports = router;
