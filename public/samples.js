/* Example code for the sample picker. These strings are only ever scanned as text. */
window.SAMPLES = {
  'js-vulnerable': {
    label: 'JavaScript: vulnerable login API',
    filename: 'vulnerable-server.js',
    code: `const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const { exec } = require("child_process");
const app = express();

const API_KEY = "sk_live_51HxAmpleKey93kdLq02";

app.get("/user", async (req, res) => {
  const rows = await db.query(\`SELECT * FROM users WHERE name = '\${req.query.name}'\`);
  document.getElementById("out").innerHTML = req.query.name;
  res.json(rows);
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/file", (req, res) => {
  fs.readFile("./uploads/" + req.query.name, (err, data) => res.send(data));
});

const hash = crypto.createHash("md5").update("secret").digest("hex");
const resetToken = Math.random().toString(36);
const result = eval(req.body.expression);
`
  },
  'js-secure': {
    label: 'JavaScript: secure counterpart',
    filename: 'secure-server.js',
    code: `const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { z } = require("zod");
const app = express();

const apiKey = process.env.API_KEY;

app.get("/user", async (req, res) => {
  const { name } = z.object({ name: z.string().max(50) }).parse(req.query);
  const rows = await db.query("SELECT * FROM users WHERE name = $1", [name]);
  document.getElementById("out").textContent = name;
  res.json(rows);
});

app.get("/ping", (req, res) => {
  const { host } = z.object({ host: z.string().regex(/^[\\w.-]+$/) }).parse(req.query);
  execFile("ping", ["-c", "1", host], (err, out) => res.send(out));
});

app.get("/file", (req, res) => {
  const base = path.resolve("uploads");
  const full = path.resolve(base, String(req.query.name));
  if (!full.startsWith(base + path.sep)) return res.sendStatus(400);
  fs.readFile(full, (err, data) => res.send(data));
});

const hash = crypto.createHash("sha256").update("data").digest("hex");
const resetToken = crypto.randomBytes(32).toString("hex");
`
  },
  'py-vulnerable': {
    label: 'Python: vulnerable Flask app',
    filename: 'vulnerable_app.py',
    code: `import hashlib
import os
import pickle
import random
import subprocess
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PASSWORD = "Sup3rS3cretPassw0rd"

@app.route("/user")
def user():
    cursor.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'")
    return render_template_string("<h1>Hello " + request.args["name"] + "</h1>")

@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args["host"])
    return "ok"

@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    data = requests.get("https://api.example.com", verify=False)
    return "loaded"

@app.route("/file")
def read_file():
    return open("uploads/" + request.args["name"]).read()

digest = hashlib.md5(b"password").hexdigest()
session_token = random.randint(100000, 999999)
app.run(debug=True)
`
  },
  'py-secure': {
    label: 'Python: secure counterpart',
    filename: 'secure_app.py',
    code: `import hashlib
import os
import json
import secrets
import subprocess
import requests
from pathlib import Path
from flask import Flask, request, render_template, abort
from pydantic import BaseModel, PositiveInt

app = Flask(__name__)
DB_PASSWORD = os.environ["DB_PASSWORD"]

@app.route("/user")
def user():
    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args["name"],))
    return render_template("hello.html", name=request.args["name"])

@app.route("/ping")
def ping():
    subprocess.run(["ping", "-c", "1", request.args["host"]], check=True)
    return "ok"

@app.route("/load", methods=["POST"])
def load():
    obj = json.loads(request.data)
    data = requests.get("https://api.example.com", verify=True)
    return "loaded"

@app.route("/file")
def read_file():
    base = Path("uploads").resolve()
    full = (base / request.args["name"]).resolve()
    if not full.is_relative_to(base):
        abort(400)
    return full.read_text()

digest = hashlib.sha256(b"data").hexdigest()
session_token = secrets.token_urlsafe(32)
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
`
  }
};
