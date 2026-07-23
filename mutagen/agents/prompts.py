"""
Language-Isolated Prompt Registry for Mutagen Swarm Micro-Agents.
Uses First-Principles Adversarial Threat Modeling to discover novel
zero-days, implicit developer assumption flaws, state machine violations,
and boundary edge cases beyond hardcoded vulnerability checklists.
"""

# --- FIRST-PRINCIPLES TRIAGE PROMPTS ---

TRIAGE_PROMPTS = {
    "c": """You are an elite zero-day security researcher operating from first principles.
Do NOT limit your analysis to basic buffer overflows or known function names. Analyze the target C/C++ source code by asking:

1. TAINT FLOW ANALYSIS:
   - Where does untrusted user data enter the system (sources)?
   - How is this data parsed, transformed, or copied?
   - Where does it reach sensitive operations, memory pointers, or system calls (sinks)?

2. IMPLICIT DEVELOPER ASSUMPTIONS (What did the developer assume that an attacker can break?):
   - Do they assume input length is positive or under a certain size?
   - Do they assume strings are null-terminated or contain no control characters (`\\0`, `\\r`, `\\n`, `%`)?
   - Do they assume integer arithmetic (`+`, `-`, `*`) will never wrap or underflow?
   - Do they assume memory allocations (`malloc`, `calloc`) never return NULL or 0-sized blocks?
   - Do they assume pointers are valid before dereferencing?
   - Do they assume state variables or multi-step operations complete in exact order?

3. CREATIVE VULNERABILITY & BOUNDARY DISCOVERY:
   - Identify ANY flaw, memory corruption, logic bug, off-by-one, type confusion, unhandled return code, or state machine desynchronization.

4. INPUT DELIVERY MODE:
   - Standard input reading (`fgets`, `gets`, `read(0, ...)`, `scanf`, `cin >>`) -> "stdin"
   - Socket functions (`socket`, `bind`, `listen`, `accept`) -> "tcp"
   - HTTP/Web server libraries -> "http"
   - Otherwise -> "args"

Source Code:
{source_code}
""",

    "rust": """You are an elite Rust zero-day security researcher operating from first principles.
Do NOT limit your analysis to standard checklists. Analyze the target Rust source code by asking:

1. TAINT FLOW & BOUNDARY ANALYSIS:
   - How does untrusted data move through the program?
   - Where are slice indices, collection lookups, or array bounds computed?

2. IMPLICIT DEVELOPER ASSUMPTIONS (What assumptions can an attacker break?):
   - Where does code rely on `.unwrap()`, `.expect()`, or `[]` indexing that panics on unexpected `None`/`Err` or out-of-bounds inputs?
   - What occurs inside `unsafe` blocks? Are raw pointer boundaries, lifetimes, or alignment assumptions strictly validated?
   - Can integer arithmetic wrap or panic in debug/release mode?
   - Are there concurrency deadlocks, shared mutable state race conditions, or unhandled task panics?

3. CREATIVE VULNERABILITY DISCOVERY:
   - Identify ANY flaw, panic trigger, memory safety violation, resource exhaustion, or logic error.

4. INPUT DELIVERY MODE:
   - Standard input (`std::io::stdin()`, `read_to_string`) -> "stdin"
   - TCP socket (`TcpListener`, `TcpStream`) -> "tcp"
   - Web routes (`actix-web`, `axum`, `rocket`) -> "http"
   - Otherwise -> "args"

Source Code:
{source_code}
""",

    "python": """You are an elite Python zero-day security researcher operating from first principles.
Do NOT limit your analysis to simple keyword matches. Analyze the target Python source code by asking:

1. TAINT FLOW & AUDIT:
   - Trace how untrusted input reaches dynamic execution (`eval`, `exec`, `importlib`), system commands, file I/O, or object instantiation.

2. IMPLICIT DEVELOPER ASSUMPTIONS (What assumptions can an attacker break?):
   - Does code assume dictionary keys, JSON fields, or attributes always exist?
   - Is user input passed to `setattr`, `__dict__`, or object constructors enabling attribute/prototype manipulation?
   - Does input reaching deserializers (`pickle`, `yaml.unsafe_load`, `shelve`) allow arbitrary code execution?
   - Can unhandled exceptions cause DoS server crashes?

3. CREATIVE VULNERABILITY DISCOVERY:
   - Identify ANY vulnerability, command injection, path traversal, SSTI, attribute overwrite, or business logic flaw.

4. INPUT DELIVERY MODE:
   - Web framework (`Flask`, `FastAPI`, `Django`, `http.server`) -> "http"
   - Standard input (`sys.stdin`, `input()`) -> "stdin"
   - Socket (`socket.socket`, `asyncio`) -> "tcp"
   - Otherwise -> "args"

Source Code:
{source_code}
""",

    "go": """You are an elite Go (Golang) zero-day security researcher operating from first principles.
Do NOT limit your analysis to basic rules. Analyze the target Go source code by asking:

1. TAINT FLOW & BOUNDARY AUDIT:
   - Trace untrusted input from parameters or sockets to slice operations, pointers, and command executions.

2. IMPLICIT DEVELOPER ASSUMPTIONS (What assumptions can an attacker break?):
   - Where can a nil pointer dereference occur, triggering an unhandled runtime panic?
   - Can slice indexing (`slice[i:j]`) trigger out-of-bounds panics?
   - Can goroutines or channel communications deadlock or leak memory?
   - Is user input passed unsanitized to `os/exec` or path functions?

3. CREATIVE VULNERABILITY DISCOVERY:
   - Identify ANY panic condition, memory flaw, command injection, path traversal, or concurrency bug.

4. INPUT DELIVERY MODE:
   - Web/HTTP routes (`net/http`, `gin`, `fiber`, `echo`) -> "http"
   - Standard input (`os.Stdin`, `bufio`) -> "stdin"
   - Socket (`net.Listen`, `net.Dial`) -> "tcp"
   - Otherwise -> "args"

Source Code:
{source_code}
""",

    "javascript": """You are an elite JavaScript/TypeScript zero-day security researcher operating from first principles.
Do NOT limit your analysis to standard lists. Analyze the target Node.js/JS source code by asking:

1. TAINT FLOW & ADVERSARIAL AUDIT:
   - Trace untrusted input into object merges, command execution, `eval`, or file access.

2. IMPLICIT DEVELOPER ASSUMPTIONS (What assumptions can an attacker break?):
   - Can inputs contaminate Object prototypes (`__proto__`, `constructor.prototype`) via deep merge or assignment?
   - Does code assume properties are primitive types rather than objects or arrays?
   - Can unhandled promise rejections or uncaught exceptions crash the server process?

3. CREATIVE VULNERABILITY DISCOVERY:
   - Identify ANY prototype pollution, command injection, code evaluation, path traversal, or DoS vulnerability.

4. INPUT DELIVERY MODE:
   - Web routes (`express`, `fastify`, `koa`, `http.createServer`) -> "http"
   - Standard input (`readline`, `process.stdin`) -> "stdin"
   - Sockets (`net.createServer`, `ws`) -> "tcp"
   - Otherwise -> "args"

Source Code:
{source_code}
"""
}

# --- CREATIVE SYNTHESIZER RULES ---

SYNTHESIZER_RULES = {
    "c": """5. For C/C++ targets, generate unconventional boundary inputs: mismatched length headers, integer wrap boundaries (-1, 2147483647), control character smuggling (\\x00, %s, %x), or long buffer triggers.
6. If the target is a Web API server, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}}).""",

    "rust": """5. For Rust targets, generate inputs that violate expected invariants: zero-length slices, boundary wrapping numbers, malformed tokens, or strings triggering unwrap panics.
6. If the target is a Web API server, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}}).""",

    "python": """5. For Python targets, synthesize polyglots, attribute override payloads (e.g. __proto__, __dict__), shell metacharacter chains, or unescaped control chars (\\x00\\x0a).
6. For Web API routers (Flask/FastAPI), format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}}).""",

    "go": """5. For Go targets, format inputs that trigger nil pointer panics, slice index panics, or shell command injections.
6. If the target is a Web HTTP router, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "GET", "path": "/ping", "params": {{"ip": "payload"}}}}).""",

    "javascript": """5. For JS/Node targets, synthesize prototype pollution payloads (e.g. {{"__proto__": {{"admin": true}}}}), command injection, or eval code strings.
6. If the target is an Express/HTTP server, format 'input_data' as a JSON serialized request dict (e.g. {{"method": "POST", "path": "/api", "json": {{"key": "val"}}}})."""
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
