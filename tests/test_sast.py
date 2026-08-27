"""Tests for the source-code SAST scanner (deluluscan/sast/)."""
import os, sys, tempfile, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.sast import SastScan  # noqa: E402
from deluluscan.models import VulnClass  # noqa: E402
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")

def scan_snip(code, ext):
    d = tempfile.mkdtemp()
    p = os.path.join(d, f"f.{ext}")
    with open(p, "w") as fh: fh.write(code)
    return SastScan().scan_file(p, f"f.{ext}")

def rules(fs): return {f.detail.get("rule") for f in fs}

def test_python_dangerous_patterns():
    code = ("import os, pickle, subprocess, hashlib\n"
            "eval(user_input)\n"
            "os.system('ping ' + host)\n"
            "subprocess.run(cmd, shell=True)\n"
            "pickle.loads(data)\n"
            "cur.execute('SELECT * FROM t WHERE id=' + uid)\n"
            "requests.get(u, verify=False)\n"
            "hashlib.md5(pw).hexdigest()\n")
    r = rules(scan_snip(code, "py"))
    for rid in ["py-eval-exec", "py-os-system", "py-shell-true", "py-pickle",
                "py-sql-format", "py-tls-verify-false", "py-weak-hash"]:
        check(f"python flags {rid}", rid in r, r)

def test_js_xss_and_injection():
    code = ('eval(x)\nel.innerHTML = data\n'
            'return <div dangerouslySetInnerHTML={{__html: html}} />\n'
            'child_process.exec("ls " + dir)\n')
    r = rules(scan_snip(code, "jsx"))
    check("js flags eval", "js-eval" in r)
    check("js flags innerHTML", "js-innerhtml" in r)
    check("js flags dangerouslySetInnerHTML", "js-dang-html" in r)

def test_java_deser_and_sql():
    code = ('ObjectInputStream in = new ObjectInputStream(s);\n'
            'stmt.executeQuery("SELECT * FROM u WHERE n=" + name);\n'
            'Runtime.getRuntime().exec(cmd);\n')
    r = rules(scan_snip(code, "java"))
    check("java flags ObjectInputStream (deser)", "java-objectinputstream" in r)
    check("java flags sql concat", "java-sql-concat" in r)
    check("java flags Runtime.exec", "java-runtime-exec" in r)

def test_secrets_integrated():
    fs = scan_snip('const K = "AKIAIOSFODNN7EXAMPLE";\n', "js")
    check("secret detected in source", any("Exposed secret" in f.title for f in fs))
    check("secret value not leaked", all("AKIAIOSFODNN7EXAMPLE" not in str(f.to_dict()) for f in fs))

def test_clean_code_is_quiet():
    code = "def add(a, b):\n    return a + b\n\nresult = add(1, 2)\n"
    check("benign code yields no findings", scan_snip(code, "py") == [], [f.title for f in scan_snip(code, "py")])

def test_line_numbers_and_class():
    fs = scan_snip("x=1\neval(y)\n", "py")
    ev = next(f for f in fs if f.detail["rule"] == "py-eval-exec")
    check("evidence has correct line number", ev.endpoint.endswith(":2"), ev.endpoint)
    check("eval maps to a valid class (misconfig)", ev.vuln_class == VulnClass.MISCONFIG)

def test_scan_path_walks_and_skips():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "src")); os.makedirs(os.path.join(d, "node_modules"))
    with open(os.path.join(d, "src", "a.py"), "w") as fh: fh.write("os.system(cmd)\n")
    with open(os.path.join(d, "node_modules", "b.py"), "w") as fh: fh.write("eval(x)\n")
    fs = SastScan().scan_path(d)
    eps = {f.endpoint for f in fs}
    check("scans src/", any("src/a.py" in e for e in eps))
    check("skips node_modules/", not any("node_modules" in e for e in eps), eps)

if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
