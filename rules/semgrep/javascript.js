const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');

const app = express();

app.get('/eval', (req, res) => {
  // ruleid: pandaward-js-eval
  eval(req.query.code);
  // ok: pandaward-js-eval
  eval("1 + 1");
  // ruleid: pandaward-js-eval
  const f = new Function('a', req.body.src);
  // ok: pandaward-js-eval
  setTimeout(() => res.end(), 10);
});

app.get('/shell', (req, res) => {
  // ruleid: pandaward-js-shell-exec
  exec(`ls ${req.query.dir}`);
  // ok: pandaward-js-shell-exec
  exec("ls -la");
  // ruleid: pandaward-js-shell-exec
  require('child_process').execSync("cat " + req.query.file);
});

app.get('/invoices/:id', async (req, res) => {
  // ruleid: pandaward-js-sql-string
  await db.query("SELECT * FROM invoices WHERE id = " + req.params.id);
  // ruleid: pandaward-js-sql-string
  await db.query(`SELECT * FROM invoices WHERE id = ${req.params.id}`);
  // ok: pandaward-js-sql-string
  await db.query("SELECT * FROM invoices WHERE id = $1", [req.params.id]);
});

function render(el, msg) {
  // ruleid: pandaward-js-html-sink
  el.innerHTML = msg;
  // ok: pandaward-js-html-sink
  el.innerHTML = "<b>static</b>";
  // ok: pandaward-js-html-sink
  el.textContent = msg;
}

function auth(token, key) {
  // ruleid: pandaward-js-jwt-none-alg
  jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
  // ok: pandaward-js-jwt-none-alg
  jwt.verify(token, key, { algorithms: ['HS256'] });
}

app.get('/proxy', async (req, res) => {
  // ruleid: pandaward-js-ssrf
  const r = await axios.get(req.query.url);
  // ok: pandaward-js-ssrf
  const s = await fetch("https://api.example.org/status");
  res.json(r.data);
});

app.get('/fetch-stored', async (req, res) => {
  const u = req.query.target;
  await db.query('insert into log (url) values ($1)', [u]);
  // ruleid: pandaward-js-ssrf
  await fetch(u);
  res.end();
});

const GITHUB_API = 'https://api.github.com';

app.get('/repos/:id', async (req, res) => {
  const repo = await db.repos.find(req.params.id);
  // A fixed origin: only path segments vary.
  // ok: pandaward-js-ssrf
  await fetch(`${GITHUB_API}/repos/${repo.nameWithOwner}/commits/${req.query.sha}`);
  // ok: pandaward-js-ssrf
  await fetch(`https://api.github.com/users/${req.params.login}`);
  // ok: pandaward-js-ssrf
  await axios.get("https://api.github.com/repos/" + req.query.repo);
  // ok: pandaward-js-ssrf
  await fetch(GITHUB_API + "/repos/" + req.query.repo);
  // The host itself comes from the request.
  // ruleid: pandaward-js-ssrf
  await fetch(`https://${req.query.host}/status`);
  // ruleid: pandaward-js-ssrf
  await fetch(`${GITHUB_API}${req.query.path}`);
  // ruleid: pandaward-js-ssrf
  await fetch(`${req.query.base}/repos/${repo.nameWithOwner}`);
  // ruleid: pandaward-js-ssrf
  await fetch("https://" + req.query.host + "/status");
  res.end();
});

async function migrate(sql) {
  const rows = await sql.query('select id, storage_key from files');
  for (const row of rows) {
    // ok: pandaward-js-ssrf
    await fetch(row.storage_key);
    // ok: pandaward-js-path-traversal
    fs.readFileSync(row.storage_key);
  }
}

app.get('/files/:name', (req, res) => {
  // ruleid: pandaward-js-path-traversal
  fs.readFile(path.join('/srv/files', req.params.name), (e, d) => res.send(d));
  // ok: pandaward-js-path-traversal
  fs.readFile(path.join('/srv/files', path.basename(req.params.name)), (e, d) => res.send(d));
});
