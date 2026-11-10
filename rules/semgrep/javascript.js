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
  // ruleid: pandaward-js-sql-injection
  await db.query("SELECT * FROM invoices WHERE id = " + req.params.id);
  // ruleid: pandaward-js-sql-injection
  await db.query(`SELECT * FROM invoices WHERE id = ${req.params.id}`);
  // ok: pandaward-js-sql-injection
  await db.query("SELECT * FROM invoices WHERE id = $1", [req.params.id]);
  // A tagged template is parameterized by the driver.
  // ok: pandaward-js-sql-injection
  await sql`SELECT * FROM invoices WHERE id = ${req.params.id}`;
});

// Dynamic SQL built in code, with no request data, is not reported (#352).
async function byId(tx, table, id) {
  // ok: pandaward-js-sql-injection
  return tx.query(`select ${USER_COLUMNS} from ${quote(table)} where u.id = $1`, [id]);
}

const OPEN_DISPUTE_STATUSES = ['open', 'needs_response'];
const INVOICES_TABLE = 'invoices';
const RETRY = { delaysMs: [100, 500, 2000] };

app.get('/reports', async (req, res) => {
  // Module constants, lists built from them and numbers carry no request data.
  // ok: pandaward-js-sql-injection
  await db.execute(sql.raw(`SELECT * FROM disputes WHERE status IN (${OPEN_DISPUTE_STATUSES.map((s) => `'${s}'`).join(', ')})`));
  // ok: pandaward-js-sql-injection
  await sql.raw(`SELECT * FROM disputes WHERE status IN (${OPEN_DISPUTE_STATUSES.map((s) => `'${s}'`).join(', ')})`);
  // ok: pandaward-js-sql-injection
  await db.query("SELECT count(*) FROM " + INVOICES_TABLE);
  // ok: pandaward-js-sql-injection
  await db.query(`DELETE FROM jobs WHERE attempts > ${Math.trunc(req.query.days)}`);
  // ok: pandaward-js-sql-injection
  await db.query("SELECT * FROM " + INVOICES_TABLE + " LIMIT " + 50);
  // ruleid: pandaward-js-sql-injection
  await db.query(`SELECT * FROM ${INVOICES_TABLE} WHERE id = ${req.query.id}`);
  // ruleid: pandaward-js-sql-injection
  await db.query("SELECT * FROM " + INVOICES_TABLE + " WHERE id = " + req.query.id);
  // ruleid: pandaward-js-sql-injection
  await db.query(req.query.where + " AND " + INVOICES_TABLE);
  // ruleid: pandaward-js-sql-injection
  await sql.raw(`SELECT * FROM t WHERE x = ${CONFIG.prefix + req.body.x}`);
  // A ternary between two string literals only picks fixed SQL text (#221).
  // ok: pandaward-js-sql-injection
  await db.query(`SET LOCAL ROLE ${req.user.isAdmin ? 'admin' : 'reader'}`);
  // ruleid: pandaward-js-sql-injection
  await db.query(`SET LOCAL ROLE ${req.user.isAdmin ? req.body.role : 'reader'}`);
  // A list built from a property of a module constant (#221).
  // ok: pandaward-js-sql-injection
  await db.query(`SELECT * FROM jobs WHERE delay_ms IN (${RETRY.delaysMs.map((ms) => Math.trunc(ms)).join(",")})`);
  // ok: pandaward-js-sql-injection
  await db.query("SELECT * FROM jobs WHERE delay_ms IN (" + RETRY.delaysMs.map((ms) => Math.trunc(ms)).join(",") + ")");
  // ruleid: pandaward-js-sql-injection
  await db.query(`SELECT * FROM jobs WHERE delay_ms IN (${req.body.delays.map((ms) => Math.trunc(ms)).join(",")})`);
  // ruleid: pandaward-js-sql-injection
  await db.query("SELECT * FROM jobs WHERE delay_ms IN (" + req.body.delays.map((ms) => Math.trunc(ms)).join(",") + ")");
  res.end();
});

const LOGO_SVG = '<svg viewBox="0 0 16 16"></svg>';
const ICONS = { close: '<svg viewBox="0 0 8 8"></svg>' };

function render(el, msg) {
  // ruleid: pandaward-js-html-sink
  el.innerHTML = msg;
  // ok: pandaward-js-html-sink
  el.innerHTML = "<b>static</b>";
  // ok: pandaward-js-html-sink
  el.textContent = msg;
  // A bare UPPER_CASE module constant is fixed markup (#220).
  // ok: pandaward-js-html-sink
  el.innerHTML = LOGO_SVG;
  // ok: pandaward-js-html-sink
  el.innerHTML = ICONS.close;
  // ruleid: pandaward-js-html-sink
  el.innerHTML = LOGO_SVG + msg;
  // ruleid: pandaward-js-html-sink
  el.insertAdjacentHTML("beforeend", LOGO_SVG + msg);
}

function topic($el, data, tag) {
  // ruleid: pandaward-js-jquery-html
  $el.find(".topic").html(data.topic);
  // ok: pandaward-js-jquery-html
  $el.html("<b>static</b>");
  // ok: pandaward-js-jquery-html
  $el.text(data.topic);
  // ruleid: pandaward-js-jquery-html
  const $msg = $("<div>" + data.msg + "</div>");
  // ruleid: pandaward-js-jquery-html
  $el.append('<p class="note">' + data.note + '</p>');
  // An element built from a tag name holds no text.
  // ok: pandaward-js-jquery-html
  const $list = $('<' + tag + '/>');
  // ok: pandaward-js-jquery-html
  $("<div></div>").text(data.msg);
  // ruleid: pandaward-js-jquery-html
  document.execCommand("insertHTML", false, data.paste);
  // ok: pandaward-js-jquery-html
  document.execCommand("bold", false, null);
  // ruleid: pandaward-js-jquery-html
  document.createElement("<input name='" + data.name + "'/>");
  // ok: pandaward-js-jquery-html
  document.createElement("input");
}

function Tooltip(element, options) {
  this.options = options;
  // ruleid: pandaward-js-jquery-plugin-option
  this.$target = $(this.options.target);
  // ruleid: pandaward-js-jquery-plugin-option
  this.$viewport = $(typeof this.options.viewport === 'function' ? this.options.viewport.call(this) : this.options.viewport);
  // ruleid: pandaward-js-jquery-plugin-option
  this.$tip.appendTo(this.options.container);
  // ok: pandaward-js-jquery-plugin-option
  this.$tip.appendTo($(document).find(this.options.container));
  // ok: pandaward-js-jquery-plugin-option
  this.$parent = $(document).find(this.options.parent);
  // The template option is markup by design.
  // ok: pandaward-js-jquery-plugin-option
  this.$tip = $(this.options.template);
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

// A library function that builds a shell command from its argument.
const cp = require('child_process');
const shell = require('shelljs');
const run = require('child_process').execSync;
function whereis(name, cb) {
  // ruleid: pandaward-js-shell-exec
  cp.exec('which ' + name, cb);
  // ruleid: pandaward-js-shell-exec
  run('ls ' + name);
  // ruleid: pandaward-js-shell-exec
  shell.exec(`git log ${name}`, { silent: true });
  // ok: pandaward-js-shell-exec
  cp.exec('which git', cb);
  // ok: pandaward-js-shell-exec
  cp.execFile('which', [name], cb);
}

// A static file server on the http module.
require('http').createServer((req, res) => {
  const file = path.join(__dirname, require('url').parse(req.url).pathname);
  // ruleid: pandaward-js-path-traversal
  fs.createReadStream(file).pipe(res);
  // ok: pandaward-js-path-traversal
  fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
  // ruleid: pandaward-js-reflected-xss
  res.end('<p>Not found: ' + req.url + '</p>');
  // ok: pandaward-js-reflected-xss
  res.end('<p>Not found: ' + escapeHtml(req.url) + '</p>');
  // ok: pandaward-js-reflected-xss
  res.end(JSON.stringify({ path: req.url }));
});

// Extracting an archive writes each entry where its name points (Zip Slip).
function extract(zip, dest) {
  zip.on('entry', (entry) => {
    // ruleid: pandaward-js-path-traversal
    entry.pipe(fs.createWriteStream(path.join(dest, entry.path)));
    // ok: pandaward-js-path-traversal
    entry.pipe(fs.createWriteStream(path.join(dest, path.basename(entry.path))));
  });
}

// A recursive merge copies every key of its input into the target.
function merge(target, source) {
  for (const key in source) {
    if (isObject(source[key])) {
      // ruleid: pandaward-js-prototype-pollution
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      // ruleid: pandaward-js-prototype-pollution
      target[key] = source[key];
    }
  }
  return target;
}

function safeMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (isObject(source[key])) {
      // ok: pandaward-js-prototype-pollution
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      // ok: pandaward-js-prototype-pollution
      target[key] = source[key];
    }
  }
  return target;
}

// A recursive copy into a fresh object cannot reach Object.prototype.
function redact(value) {
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    // ok: pandaward-js-prototype-pollution
    out[k] = typeof v === 'object' ? redact(v) : v;
  }
  return out;
}

// A shallow copy does not recurse, so it cannot reach Object.prototype.
function copy(target, source) {
  for (const key in source) {
    // ok: pandaward-js-prototype-pollution
    target[key] = source[key];
  }
  return target;
}

// A payload's .body built for an outgoing call is not request data (#352).
async function pspCall(keys, path, body) {
  const opts = { body: JSON.stringify(body) };
  // ok: pandaward-js-ssrf
  return fetch(`${keys.base}${path}`, { method: 'POST', body: opts.body });
}
