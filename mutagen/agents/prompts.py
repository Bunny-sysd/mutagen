"""
Language-Isolated Prompt Registry for Mutagen Swarm Micro-Agents.
Guarantees that target code only receives security audit prompts,
vulnerability heuristics, payload rules, and patch guidelines tailored
strictly to its runtime and language semantics.
"""

# --- TRIAGE PROMPTS ---

TRIAGE_PROMPTS = {
    "rust": """You are an expert Rust security auditor.
Analyze the provided Rust source code and:
1. Identify memory safety and crash vulnerabilities specific to Rust:
   - Improper `unsafe` blocks or raw pointer dereferences
   - Out-of-bounds array/slice indexing triggering runtime `panic!`
   - Unhandled `.unwrap()` or `.expect()` calls on `None`/`Err` leading to DoS panics
   - Integer overflow/underflow in release/debug builds
   - Concurrency deadlocks or data races
2. Determine how the target receives input:
   - Standard input reading (`std::io::stdin()`, `read_to_string`) -> "stdin"
   - TCP socket bindings (`TcpListener`, `TcpStream`) -> "tcp"
   - Web framework routes (`actix-web`, `axum`, `rocket`) -> "http"
   - Command line arguments (`std::env::args`, `clap`) -> "args"

Source Code:
{source_code}
""",

    "python": """You are an expert Python security auditor.
Analyze the provided Python source code and:
1. Identify vulnerabilities specific to Python:
   - OS Command Injection (`os.system`, `subprocess.run(..., shell=True)`, `os.popen`)
   - Arbitrary Attribute Overwrite (`setattr`, `__dict__` manipulation)
   - Unsafe Deserialization (`pickle.loads`, `yaml.unsafe_load`)
   - Code execution via `eval()`, `exec()`, or dynamic imports
   - Server-Side Template Injection (SSTI) or Path Traversal
2. Determine how the target receives input:
   - Web framework routes (`Flask`, `FastAPI`, `Django`, `http.server`) -> "http"
   - Standard input (`sys.stdin.read`, `input()`) -> "stdin"
   - Sockets (`socket.socket`, `asyncio.start_server`) -> "tcp"
   - Command line arguments (`sys.argv`, `argparse`) -> "args"

Source Code:
{source_code}
""",

    "go": """You are an expert Go (Golang) security auditor.
Analyze the provided Go source code and:
1. Identify vulnerabilities specific to Go:
   - Nil pointer dereferences triggering runtime panics
   - Slice bounds out of range panics
   - OS Command Injection (`os/exec.Command("sh", "-c", ...)`)
   - Unhandled channel deadlocks or goroutine leaks
   - Path traversal or unsafe `unsafe.Pointer` usage
2. Determine how the target receives input:
   - Web framework / HTTP routes (`net/http`, `gin`, `fiber`, `echo`) -> "http"
   - Standard input (`os.Stdin`, `bufio.NewScanner`) -> "stdin"
   - Sockets (`net.Listen`, `net.Dial`) -> "tcp"
   - Command line arguments (`os.Args`, `flag`) -> "args"

Source Code:
{source_code}
""",

    "javascript": """You are an expert JavaScript/TypeScript security auditor.
Analyze the provided Node.js/JS source code and:
1. Identify vulnerabilities specific to JavaScript/TypeScript:
   - Prototype Pollution (`Object.assign`, deep merge, `__proto__` injection)
   - OS Command Injection (`child_process.exec`, `child_process.spawn(..., {shell: true})`)
   - Code execution via `eval()`, `new Function()`, `vm.runInContext`
   - Unhandled promise rejections or server crash panics
   - Path Traversal (`fs.readFile` with user input)
2. Determine how the target receives input:
   - Web framework routes (`express`, `fastify`, `koa`, `http.createServer`) -> "http"
   - Standard input (`readline`, `process.stdin`) -> "stdin"
   - Sockets (`net.createServer`, `ws`) -> "tcp"
   - Command line arguments (`process.argv`, `commander`) -> "args"

Source Code:
{source_code}
""",

    "c": """You are an expert C/C++ security auditor.
Analyze the provided C/C++ source code and:
1. Identify memory corruption vulnerabilities:
   - Stack/Heap Buffer Overflows (`strcpy`, `strcat`, `sprintf`, `gets`, unchecked loops)
   - Format String vulnerabilities (`printf(user_input)`)
   - Use-After-Free (UAF) or Double Free
   - Off-by-one errors or Integer Overflows leading to allocation errors
   - Command Injection (`system()`, `popen()`)
2. Determine how the target receives input:
   - Standard input (`fgets`, `gets`, `read(0, ...)`, `scanf`, `cin >>`) -> "stdin"
   - Socket functions (`socket`, `bind`, `listen`, `accept`) -> "tcp"
   - HTTP/Web server libraries -> "http"
   - Command line arguments (`argv`, `argc`, `getopt`) -> "args"

Source Code:
{source_code}
"""
}

# --- SYNTHESIZER PROMPTS ---

SYNTHESIZER_RULES = {
    "rust": """5. For Rust targets, format payloads that trigger slice boundary panics, unwrap panics, or input strings that reach unsafe blocks.
6. If the target is a Web API server, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}}).""",

    "python": """5. For custom binary protocol targets, format 'input_data' using standard Python string escape sequences (e.g. \\x20\\x00\\x0eis_admin=true).
6. For Web API routers (Flask/FastAPI/http.server), format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}} or {{"method": "POST", "path": "/api/config", "json": {{"key": "val"}}}}).""",

    "go": """5. For Go targets, format payloads that trigger nil pointer panics, array slice index panics, or command injection args.
6. If the target is a Web HTTP router, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}}).""",

    "javascript": """5. For JS/Node targets, format payloads that trigger prototype pollution (e.g. {{"__proto__": {{"admin": true}}}}), command injection, or eval payloads.
6. If the target is an Express/HTTP server, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "POST", "path": "/api", "json": {{"key": "val"}}}}).""",

    "c": """5. For C/C++ targets, format binary buffers, long overflow strings (e.g. 200 'A's), or format specifiers (e.g. %x%x%s) to trigger memory crashes or signal violations."""
}

def get_triage_prompt(language: str, source_code: str) -> str:
    lang_key = (language or "c").lower()
    if lang_key in ("cpp", "c++"):
        lang_key = "c"
    elif lang_key in ("typescript", "ts"):
        lang_key = "javascript"

    template = TRIAGE_PROMPTS.get(lang_key, TRIAGE_PROMPTS["c"])
    return template.format(source_code=source_code)

def get_synthesizer_rules(language: str) -> str:
    lang_key = (language or "c").lower()
    if lang_key in ("cpp", "c++"):
        lang_key = "c"
    elif lang_key in ("typescript", "ts"):
        lang_key = "javascript"

    return SYNTHESIZER_RULES.get(lang_key, SYNTHESIZER_RULES["c"])
