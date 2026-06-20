from mutagen.chunker import split_functions, contains_dangerous_keywords, filter_functions, reconstruct_pseudo_code

def test_split_functions():
    pseudo_code = """// ============================================
// MUTAGEN DECOMPILED OUTPUT
// Binary: test.exe
// Format: PE
// Architecture: x86
// Compiler: gcc
// ============================================

// --- Function: main @ 00401000 ---
int main(int argc, char **argv) {
    char buf[128];
    strcpy(buf, argv[1]);
    return 0;
}

// --- Function: utility @ 00402000 ---
void utility() {
    int x = 10;
}
"""
    meta, funcs = split_functions(pseudo_code)
    
    assert "MUTAGEN DECOMPILED OUTPUT" in meta
    assert len(funcs) == 2
    
    assert funcs[0]["name"] == "main"
    assert funcs[0]["address"] == "00401000"
    assert "strcpy" in funcs[0]["code"]
    
    assert funcs[1]["name"] == "utility"
    assert funcs[1]["address"] == "00402000"
    assert "int x = 10;" in funcs[1]["code"]

def test_contains_dangerous_keywords():
    code_vuln = "void vuln() { strcpy(a, b); }"
    code_safe = "void safe() { int x = 5; }"
    
    assert contains_dangerous_keywords(code_vuln) is True
    assert contains_dangerous_keywords(code_safe) is False

def test_filter_functions():
    funcs = [
        {"name": "main", "address": "1", "code": "void main() {}"},
        {"name": "helper", "address": "2", "code": "void helper() { int y = 20; }"},
        {"name": "vuln_action", "address": "3", "code": "void vuln() { VirtualAlloc(); }"}
    ]
    
    filtered = filter_functions(funcs)
    assert len(filtered) == 2
    assert filtered[0]["name"] == "main"
    assert filtered[1]["name"] == "vuln_action"

def test_reconstruct_pseudo_code():
    meta = "// Test Header"
    funcs = [
        {"name": "func1", "address": "100", "code": "void func1() {}"}
    ]
    reconstructed = reconstruct_pseudo_code(meta, funcs)
    assert "// Test Header" in reconstructed
    assert "// --- Function: func1 @ 100 ---" in reconstructed
    assert "void func1() {}" in reconstructed
