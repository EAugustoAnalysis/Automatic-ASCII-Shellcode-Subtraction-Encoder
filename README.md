# Automatic ASCII Shellcode Subtraction Encoder
Generates printable ASCII subtraction encoded shellcode for NASM.
Installation
```
$ git clone https://github.com/EAugustoAnalysis/Automatic-ASCII-Shellcode-Subtraction-Encoder.git
$ cd Automatic-ASCII-Shellcode-Subtraction-Encoder
# pip3 install z3-solver
$ python3 encoder.py
```
Based on Marcos Valle's z3ncoder, which can ASCII encode a 32 bit address:
https://github.com/marcosValle/z3ncoder

Usage
```
$ python3 encoder.py -s [shellcode]
```

Example
```
$ python3 encoder.py -s 6681caff0f42526a0258cd2e3c055a74efb8543030578bfaaf75eaaf75e7ffe7
```

Outputs assembly to aassc.asm, gives additional information on terminal.

Note: Shellcode length must be a multiple of 4, nop padding can accomplish this. Shellcode must be in hex format.

This script will not generate the instructions required to reserve stack space for the decoded shellcode.

- Used to exploit LTER in Vulnserver with shellcode containing null bytes (unencoded MSFVenom Reverse Shell).
- Confirmed working with most MSFVenom x86 encoders.

Known Compatibility Issues
- When used with MSFVenom Shikata_ga_nai encoder, has an unexplained tendency to generate odd instructions and overwrite the EIP.

Coming Soon:
- Verbosity settings
- Custom badchars, (currently badchars are 00, 20, 0a, 0d, 3a, 3f, and any character that's not printable, valid ASCII)
- Custom output files
