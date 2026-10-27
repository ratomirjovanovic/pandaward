const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');

const app = express();

app.get('/eval', (req, res) => {
  // ruleid: pensec-js-eval
  eval(req.query.code);
  // ok: pensec-js-eval
  eval("1 + 1");
  // ruleid: pensec-js-eval
  const f = new Function('a', req.body.src);
  // ok: pensec-js-eval
  setTimeout(() => res.end(), 10);
});

app.get('/shell', (req, res) => {
  // ruleid: pensec-js-shell-exec
  exec(`ls ${req.query.dir}`);
  // ok: pensec-js-shell-exec
  exec("ls -la");
  // ruleid: pensec-js-shell-exec
  require('child_process').execSync("cat " + req.query.file);
});

app.get('/invoices/:id', async (req, res) => {
  // ruleid: pensec-js-sql-string
  await db.query("SELECT * FROM invoices WHERE id = " + req.params.id);
  // ruleid: pensec-js-sql-string
  await db.query(`SELECT * FROM invoices WHERE id = ${req.params.id}`);
  // ok: pensec-js-sql-string
  await db.query("SELECT * FROM invoices WHERE id = $1", [req.params.id]);
});

function render(el, msg) {
  // ruleid: pensec-js-html-sink
  el.innerHTML = msg;
  // ok: pensec-js-html-sink
  el.innerHTML = "<b>static</b>";
  // ok: pensec-js-html-sink
  el.textContent = msg;
}

function auth(token, key) {
  // ruleid: pensec-js-jwt-none-alg
  jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
  // ok: pensec-js-jwt-none-alg
  jwt.verify(token, key, { algorithms: ['HS256'] });
}

app.get('/proxy', async (req, res) => {
  // ruleid: pensec-js-ssrf
  const r = await axios.get(req.query.url);
  // ok: pensec-js-ssrf
  const s = await fetch("https://api.example.org/status");
  res.json(r.data);
});

app.get('/files/:name', (req, res) => {
  // ruleid: pensec-js-path-traversal
  fs.readFile(path.join('/srv/files', req.params.name), (e, d) => res.send(d));
  // ok: pensec-js-path-traversal
  fs.readFile(path.join('/srv/files', path.basename(req.params.name)), (e, d) => res.send(d));
});
