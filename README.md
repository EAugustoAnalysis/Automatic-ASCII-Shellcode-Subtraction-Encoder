# Automatic-ASCII-Shellcode-Subtraction-Encoder
Generates ASCII encoded shellcode for NASM.
Installation
```
$ git clone https://github.com/EAugustoAnalysis/Automatic-ASCII-Shellcode-Subtraction-Encoder.git
$ cd Automatic-ASCII-Shellcode-Subtraction-Encoder
# pip3 install z3-solver
$ python3 encode.py
```
Based on Marcos Valle's z3ncoder, which can ASCII encode a 32 bit address:
https://github.com/marcosValle/z3ncoder

Usage
```
$ python3 encode.py -s [Null free shellcode]
```
Outputs assembly to aassc.asm, gives breakdown on terminal
Note: Shellcode length must be a multiple of 4, nop padding can accomplish this. Hex format only for now.

Coming Soon:
- Verbosity settings
- Badchar Adaptability, currently badchars are 00, 20, 0a, 0d, 3a, 3f, and anything that's not valid ASCII
- Custom output files
