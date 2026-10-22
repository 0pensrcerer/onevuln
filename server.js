const express = require('express');
const serialize = require('node-serialize');

const app = express();

// VULNERABLE: untrusted query param deserialized without validation (CWE-502)
app.get('/profile', (req, res) => {
  const user = serialize.unserialize(req.query.data);
  res.json(user);
});

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
