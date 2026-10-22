const express = require('express');
const serialize = require('node-serialize');

const app = express();
app.use(require('./vulns2'));

const orders = {
  1001: { owner: 'alice', total: 42.50 },
  1002: { owner: 'bob', total: 99.00 },
};

app.get('/profile', (req, res) => {
  const user = serialize.unserialize(req.query.data);
  res.json(user);
});

// VULNERABLE: returns any order by id with no ownership check (IDOR, CWE-639)
app.get('/orders/:id', (req, res) => {
  res.json(orders[req.params.id]);
});

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
