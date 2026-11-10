import base64
import codecs
import configparser
import hashlib
import os
import pickle
import random
import secrets
import subprocess
import xml.dom.minidom
import xml.sax
import xml.sax.handler

import flask
import lxml.etree
import requests
import yaml
from flask import Flask, make_response, redirect, render_template_string, request, send_file, session, url_for
from ldap3.utils.conv import escape_filter_chars
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/eval", methods=["POST"])
def evaluate():
    code = request.form.get("code")
    # ruleid: pandaward-py-eval
    eval(code)
    # ok: pandaward-py-eval
    eval("1 + 1")
    return "done"


def run_tool_call(client):
    completion = client.chat.completions.create(model="m", messages=[])
    # ruleid: pandaward-py-eval
    eval(completion.choices[0].message.content)
    message = client.messages.create(model="m", max_tokens=100, messages=[])
    # ruleid: pandaward-py-shell
    subprocess.run(message.content[0].text, shell=True)


@app.route("/shell")
def shell():
    name = request.args.get("name")
    # ruleid: pandaward-py-shell
    subprocess.run("ls " + name, shell=True)
    args = ["sh", "-c"]
    args.append(f"echo {name}")
    # ruleid: pandaward-py-shell
    subprocess.run(args)
    # ruleid: pandaward-py-shell
    os.system(f"rm {name}")
    # ok: pandaward-py-shell
    os.system("ls")
    # ok: pandaward-py-shell
    subprocess.run(["ls", "/srv"])
    return "done"


@app.route("/invoice")
def lookup():
    invoice_id = request.cookies.get("invoice")
    cur = get_cursor()
    # ruleid: pandaward-py-sql-injection
    cur.execute("SELECT * FROM invoices WHERE id = %s" % invoice_id)
    conf = configparser.ConfigParser()
    conf.add_section("q")
    conf.set("q", "id", invoice_id)
    # ruleid: pandaward-py-sql-injection
    cur.execute(f"SELECT * FROM invoices WHERE id = {conf.get('q', 'id')}")
    # ok: pandaward-py-sql-injection
    cur.execute("SELECT * FROM invoices WHERE id = %s", (invoice_id,))
    return "done"


@app.route("/load", methods=["POST"])
def load():
    data = request.form.get("data")
    # ruleid: pandaward-py-unsafe-deserialization
    obj = pickle.loads(base64.urlsafe_b64decode(data))
    # ruleid: pandaward-py-unsafe-deserialization
    cfg = yaml.load(data, Loader=yaml.Loader)
    # ok: pandaward-py-unsafe-deserialization
    cfg = yaml.load(data, Loader=yaml.SafeLoader)
    # ok: pandaward-py-unsafe-deserialization
    cfg = yaml.safe_load(data)
    return "done"


def load_cache(path):
    with open(path, "rb") as f:
        # ruleid: pandaward-py-unsafe-deserialization
        return pickle.load(f)


def fetch():
    # ruleid: pandaward-py-tls-verify-off
    requests.get("https://example.org", verify=False)
    # ok: pandaward-py-tls-verify-off
    requests.get("https://example.org")


@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    # ruleid: pandaward-py-ssrf
    r = requests.get(url)
    # ok: pandaward-py-ssrf
    s = requests.get("https://api.example.org/status")
    return "done"


@app.route("/files")
def files():
    name = request.args.get("name")
    # ruleid: pandaward-py-path-traversal
    f = codecs.open(f"/srv/files/{name}", "r", "utf-8")
    # ruleid: pandaward-py-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/files-safe")
def files_safe():
    name = secure_filename(request.args.get("name"))
    # ok: pandaward-py-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/people")
def people():
    uid = request.args.get("uid")
    conn = get_ldap()
    # ruleid: pandaward-py-ldap-injection
    conn.search("ou=users", f"(uid={uid})")
    # ok: pandaward-py-ldap-injection
    conn.search("ou=users", f"(uid={escape_filter_chars(uid)})")
    return "done"


@app.route("/employee")
def employee():
    emplid = request.args.get("id")
    root = lxml.etree.parse("employees.xml")
    # ruleid: pandaward-py-xpath-injection
    nodes = root.xpath(f"/Employees/Employee[@emplid='{emplid}']")
    # ok: pandaward-py-xpath-injection
    nodes = root.xpath("/Employees/Employee[@emplid=$id]", id=emplid)
    return "done"


@app.route("/search")
def search():
    q = request.args.get("q")
    if q == "":
        # ok: pandaward-py-xss
        return f"No query, try {escape(q)}"
    # ruleid: pandaward-py-xss
    return f"Results for {q}"


@app.route("/search2")
def search2():
    q = request.args.get("q")
    # ruleid: pandaward-py-xss
    return make_response("Results for " + q)


@app.route("/next")
def next_page():
    target = request.args.get("next")
    if target == "home":
        # ok: pandaward-py-open-redirect
        return redirect(url_for("home"))
    # ruleid: pandaward-py-open-redirect
    return redirect(target)


@app.route("/remember", methods=["POST"])
def remember():
    role = request.form.get("role")
    # ruleid: pandaward-py-trust-boundary
    flask.session["role"] = role
    # ok: pandaward-py-trust-boundary
    flask.session["visited"] = True
    return "done"


@app.route("/xml", methods=["POST"])
def parse_xml():
    body = request.form.get("doc")
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    # ruleid: pandaward-py-xxe
    doc = xml.dom.minidom.parseString(body, parser)
    return "done"


@app.route("/xml-safe", methods=["POST"])
def parse_xml_safe():
    body = request.form.get("doc")
    parser = xml.sax.make_parser()
    # ok: pandaward-py-xxe
    doc = xml.dom.minidom.parseString(body, parser)
    return "done"


@app.route("/hello")
def hello():
    # ruleid: pandaward-py-template-injection
    page = render_template_string("<h1>Hello " + request.args.get("name") + "</h1>")
    # ok: pandaward-py-template-injection
    page = render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name"))
    return page


def digests(data):
    # ruleid: pandaward-py-weak-hash
    a = hashlib.md5(data)
    # ruleid: pandaward-py-weak-hash
    b = hashlib.new("sha1")
    # ok: pandaward-py-weak-hash
    c = hashlib.sha256(data)
    # ok: pandaward-py-weak-hash
    d = hashlib.md5(data, usedforsecurity=False)


def tokens():
    # ruleid: pandaward-py-weak-random
    a = random.getrandbits(64)
    # ruleid: pandaward-py-weak-random
    b = random.random()
    # ok: pandaward-py-weak-random
    c = secrets.token_urlsafe(32)


@app.route("/cookie")
def cookie():
    resp = make_response("ok")
    # ruleid: pandaward-py-insecure-cookie
    resp.set_cookie("session", "x", secure=False, httponly=True)
    # ok: pandaward-py-insecure-cookie
    resp.set_cookie("session", "x", secure=True, httponly=True)
    return resp
