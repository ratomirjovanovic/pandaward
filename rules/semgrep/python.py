import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)


def evaluate(code):
    # ruleid: pandaward-py-eval
    eval(code)
    # ok: pandaward-py-eval
    eval("1 + 1")


def shell(name):
    # ruleid: pandaward-py-shell
    subprocess.run("ls " + name, shell=True)
    # ok: pandaward-py-shell
    subprocess.run(["ls", name])
    # ruleid: pandaward-py-shell
    os.system(f"rm {name}")
    # ok: pandaward-py-shell
    os.system("ls")


def lookup(cur, invoice_id):
    # ruleid: pandaward-py-sql-string
    cur.execute("SELECT * FROM invoices WHERE id = %s" % invoice_id)
    # ruleid: pandaward-py-sql-string
    cur.execute(f"SELECT * FROM invoices WHERE id = {invoice_id}")
    # ok: pandaward-py-sql-string
    cur.execute("SELECT * FROM invoices WHERE id = %s", (invoice_id,))


def load(data, text):
    # ruleid: pandaward-py-unsafe-deserialization
    obj = pickle.loads(data)
    # ruleid: pandaward-py-unsafe-deserialization
    cfg = yaml.load(text)
    # ok: pandaward-py-unsafe-deserialization
    cfg = yaml.load(text, Loader=yaml.SafeLoader)
    # ok: pandaward-py-unsafe-deserialization
    cfg = yaml.safe_load(text)


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
    return r.text


@app.route("/files")
def files():
    name = request.args.get("name")
    # ruleid: pandaward-py-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/files-safe")
def files_safe():
    name = secure_filename(request.args.get("name"))
    # ok: pandaward-py-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/hello")
def hello():
    # ruleid: pandaward-py-template-injection
    page = render_template_string("<h1>Hello " + request.args.get("name") + "</h1>")
    # ok: pandaward-py-template-injection
    page = render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name"))
    return page
