# Mutagen Fuzzing Targets Directory

This directory contains test-bed targets for verifying Mutagen fuzzer capabilities, AI crash triggers, and auto-patch validation.

---

## Target Index

| File | Vulnerability / Challenge Type | Delivery Mode |
| --- | --- | --- |
| `01_buffer_overflow.c` | Stack Buffer Overflow (`strcpy`) | argv |
| `02_format_string.c` | Format String Vulnerability (`printf`) | argv |
| `03_integer_overflow.c` | Integer Wrap to Heap Buffer Overflow (`malloc`) | argv |
| `04_use_after_free.c` | Use After Free (Dangling Pointer dereference) | stdin |
| `05_integer_overflow.c` | Signed Integer Overflow check bypass | argv |
| `06_complex_logic.c` | State-dependent logic trigger path | argv |
| `07_double_free.c` | Double Free memory corruptor | argv |
| `08_off_by_one.c` | Null Terminator Off-by-one check | argv |
| `09_network_server.c` | TCP Socket Buffer Overflow | tcp:8080 |
| `09_stdin_target.c` | Simple stdin reader Stack Overflow | stdin |
| `10_null_dereference.c` | Null Pointer Dereference panic | argv |
| `11_complex_auth.c` | Logical authentication check bypass | argv |
| `12_custom_parser.c` | Length-value field out-of-bounds read | argv |
| `13_long_db_parser.c` | Database field separator escape parser | argv |
| `14_complex_2026_challenge.c` | Complex nested loop arithmetic overflow | argv |
| `15_interpreter_vm_oob.c` | VM Opcode Interpreter array index OOB | argv |
| `16_cve_2026_6691_mongoc_sasl.c` | libmongoc Cyrus SASL callback heap-overflow | argv |

---

## Compilation and Usage

When testing a target directly, Mutagen automatically compiles it using local compilers (GCC/MinGW, Rust, Go, or .NET) or isolates it inside Docker sandbox mode if `--sandbox docker` is specified.

To manually fuzz a target (e.g., target 16):
```bash
python mutagen.py -t targets/16_cve_2026_6691_mongoc_sasl.c --max-payloads 3 --coverage
```
