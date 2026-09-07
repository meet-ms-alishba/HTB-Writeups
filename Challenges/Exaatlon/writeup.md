# Hack The Box - Exatlon Writeup

**Challenge Name:** Exatlon  
**Category:** Reverse Engineering  
**Difficulty:** Easy  

---

## Technical Overview

Exatlon is an entry-level ELF binary reverse engineering challenge. The application takes a user-supplied string, processes each character through a deterministic bitwise transformation routine, and checks the resulting array against a static sequence of integers.

---

## 1. File Inspection & Unpacking

Starting with initial triage on the provided archive file:

```bash
# Extract the binary package
unzip a12c73b2-ba28-4714-8644-8d3fe0b29b99.zip

# Inspect binary properties
file exatlon_v1
Executing file indicates the binary is an ELF 64-bit executable. Checking section headers or running strings reveals UPX signatures, indicating packed code.To unpack the binary for static decompilation:Bashupx -d exatlon_v1
2. Static Analysis & Reverse EngineeringOpening the unpacked executable in Ghidra/IDA shows the primary execution flow inside main:Banner & Prompt: The binary displays an ASCII art banner using sleep() calls between lines to delay output, then prompts for the password input.Character Transformation Routine (exatlon): The input string is iterated character-by-character. Each character value $c$ is passed through a transformation function that applies a 4-bit left shift:$$\text{encoded\_char} = c \ll 4$$Mathematically, shifting a binary number left by 4 bits is equivalent to multiplying by $2^4$ ($16$):$$\text{encoded\_char} = c \times 16$$Validation Check: The transformed integers are compared sequentially against a hardcoded integer array stored at memory location 0x54B4F0:Plaintext1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000
3. Reversing the Encoding SchemeSince the bitwise left-shift operation $c \ll 4$ corresponds directly to $c \times 16$, the original ASCII character value $c$ is recovered using exact integer division:$$c = \frac{\text{encoded\_char}}{16}$$4. Solve ScriptThe following Python script extracts the hardcoded integer array, performs the inverse operation ($\text{val} \mathbin{//} 16$), and outputs the reconstructed flag:Python#!/usr/bin/env python3

# Target encoded array extracted from binary memory
encoded_flag = [
    1152, 1344, 1056, 1968, 1728, 816, 1648, 784, 1584, 816, 
    1728, 1520, 1840, 1664, 784, 1632, 1856, 1520, 1728, 816, 
    1632, 1856, 1520, 784, 1760, 1840, 1824, 816, 1584, 1856, 
    784, 1776, 1760, 528, 528, 2000
]

# Reconstruct ASCII characters
flag = "".join(chr(val // 16) for val in encoded_flag)

print(f"[+] Flag: {flag}")
Execution OutputBash$ python3 solve.py
[+] Flag: HTB{...}
Key TakeawaysPacking Detection: Always inspect executable headers for UPX or custom packers prior to disassembly.Algebraic Equivalences: Recognizing bitwise arithmetic primitives ($x \ll n \equiv x \times 2^n$) allows linear encoding routines to be inverted without requiring dynamic debugging or symbolic execution solvers.
