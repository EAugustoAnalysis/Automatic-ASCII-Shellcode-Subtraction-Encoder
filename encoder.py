#Automatic ASCII Shellcode Subtraction Encoder
#Expands on BUGTREE's z3ncoder, which can encode individual 32 bit hex addresses, by taking in a full shellcode payload and outputting assembly
#Written by Elias Augusto

import argparse
from z3 import *
from colorama import Fore,Back,Style

#Remember to give it a help dialogue and the ability to check if an string length is a multiple of 8
#It can advise padding with nops if not

def solve(b,bc): #BUGTREE's function that sub encodes 32 bit hex addresses in 0xFFFFFFFF format
    s = Solver()
    bad_chars = [ 0x20, 0x80, 0x0A, 0x0D, 0x2F, 0x3A, 0x3F ]
    bad_chars+=bc #I added ability to specify additional badchars
    x, y, z = BitVecs('x y z', 32)
    variables = [x, y, z]

    for var in variables:
        for k in range(0, 32, 8):
            s.add(Extract(k+7, k, var) > BitVecVal(0x20, 8))
            s.add(ULT(Extract(k+7, k, var), BitVecVal(0x80, 8)))
            for c in bad_chars:
                s.add(Extract(k+7, k, var) != BitVecVal(c, 8))

    s.add(x+y+z==b)

    s.check()
    s.model()
    r = []
    for i in s.model():
        r.append(s.model()[i].as_long())

    return r

parser = argparse.ArgumentParser() #Argument that takes shellcode 
parser.add_argument("-s", "--shellcode", type=str,
                    help="Input hex shellcode with a byte length of a multiple of 4 or use -p flag to pad automatically.")
parser.add_argument("-b", "--badchars", type=str,
                    help="Input badchars in comma separated format: -b \"0x01,0x02,0x03\". Note that too many additional badchars may cause code generation to fail. Default badchars (immutable): Any non-printable non-valid ASCII, 0x00,0x0a,0x0b,0x20,0x3A,0x3F.")
parser.add_argument("-n", "--normalizer", type=str,
                    help="Some characters cannot be removed through use of the -b command because they are used to normalize eax. To remove these characters, insert custom, pre-tested instructions to normalize eax in this format: -n \"and eax,0x222222222\\nand eax,0x22222222\". Instructions do not need to be valid.")
parser.add_argument("-f", "--file", type=str,
                    help="Output file for assembly code. Otherwise, it will only appear on the terminal. Format: -f file.asm")
parser.add_argument("-p", "--pad", action="store_true",
                    help="Automatically pads shellcode with nops to ensure length is a multiple of 4.")
args = parser.parse_args()

if not args.shellcode: #Exit if no shellcode given
	parser.print_help()
	parser.exit()

scode=args.shellcode
if args.pad:
	if len(scode)%2==0:
		while len(scode)%8!=0:
			scode+="90"
	else:
		parser.error("Malformed or invalid machine language")	
		
if len(scode)%8!=0: #Exit if shellcode length is less than 4
	parser.error("Shellcode byte length is not a multiple of 4, pad shellcode and retry.")

bdchars=[]
if args.badchars:
	bcharstxt=args.badchars.split(",")
	bdchars+=[int(x,16) for x in bcharstxt]
	

splitsc=[''.join(x) for x in zip(*[list(scode[z::8]) for z in range(8)])] #Split into fours
print(Fore.GREEN+"\nAutomatic ASCII Shellcode Subtraction Encoder")
print(Fore.GREEN+"Written by Elias Augusto")
print(Fore.GREEN+"Based on BUGTREE's z3ncoder, a single address subtraction encoder")
if args.file:
	print(Fore.GREEN+"Assembly output file: "+args.file)
print(Fore.GREEN+"\n--------------------------------------------------------------------\n")

print(Fore.GREEN+"Original shellcode:\n")
print(Fore.WHITE+'\n'.join(splitsc))

rsplit=[]
for i in range(0,len(splitsc)): #split each line of shellcode, reverse each byte
	fsplit=[''.join(x) for x in zip(*[list(splitsc[i][z::2]) for z in range(2)])]
	lsplit=fsplit[::-1]
	rsplit+=''.join(map(str,lsplit))

unsplit=''.join(rsplit) #Join rsplit into one string
resplit=[''.join(x) for x in zip(*[list(unsplit[z::8]) for z in range(8)])] #split it into strings of 4 bytes again

for i in range(0,len(resplit)):
	resplit[i]="0x"+resplit[i]

reversesc=resplit[::-1] #Reverse the order of the elements to push to the stack

print(Fore.GREEN+"\n--------------------------------------------------------------------\n")
print(Fore.GREEN+"Shellcode Reversed and Formatted for Stack:\n")
print(Fore.WHITE+'\n'.join(reversesc))

hexsc=reversesc
reciporical=[None]*len(hexsc)
for i in range(0,len(hexsc)): #Get the reciporical of every hex string aftr converting it to an int
	hexsc[i]=int(hexsc[i],16)
	f=hexsc[i]
	reciporical[i]=0xFFFFFFFF-f + 1

precip=reciporical
for i in range(0,len(precip)):
	precip[i]=hex(precip[i])
print(Fore.GREEN+"\n--------------------------------------------------------------------\n")
print(Fore.GREEN+"Reciporical of each chunk:\n")
print(Fore.WHITE+'\n'.join(precip))

print(Fore.GREEN+"\n--------------------------------------------------------------------\n")
print(Fore.GREEN+"Assembly Output")
buffer=""
if args.file:
	print(Fore.GREEN+"Sent to file: "+args.file+"\n")
	buffer+=";Filename: "+args.file+"\n"
buffer+=";Intel assembly output for NASM\n"
buffer+=";Generated by Automatic ASCII Shellcode Subtraction Encoder\n\n"
buffer+=";Unencoded payload = "+args.shellcode+"\n\n"
if args.badchars:
	buffer+=";Custom badchars: "+args.badchars+"\n"
buffer+=";Note: You still need to set up the stack yourself, this is just the decoder\n\n"
buffer+="global _start\n_start:\n\n"

for i in range(0,len(reciporical)): #Assembly output
	if precip[i]=='0x100000000':
		buffer+=";~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
		buffer+=";Line of nulls\n\n"
		if args.normalizer:
			norm=args.normalizer.split("\\n")
			for i in range(0,len(norm)):
				buffer+=norm[i]
				buffer+="\n"
		else:
			buffer+="and eax,0x554e4d4a ;normalize eax\n"
			buffer+="and eax,0x2a313235 ;normalize eax\n"
		buffer+="push eax\n\n"
	else:
		sumCheck=0
		result=solve(int(reciporical[i],16),bdchars)
		for h in result[-3:]:
			sumCheck+=h
		sumChecktext=hex(sumCheck)
		checksum=sumChecktext
		if len(sumChecktext)==11: #remove annoying extra byte that sometimes appears and does not effect acccuracy
			checksum=sumChecktext.replace('1','',1)
		buffer+=";~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
		buffer+=";0xFFFFFFFF - "+hex(reversesc[i])+" + 1 = "+precip[i]+"\n"
		buffer+=";Verified: "+checksum+" = "+precip[i]+"\n\n"
		if args.normalizer:
			norm=args.normalizer.split("\\n")
			for i in range(0,len(norm)):
				buffer+=norm[i]
				buffer+="\n"
		else:
			buffer+="and eax,0x554e4d4a ;normalize eax\n"
			buffer+="and eax,0x2a313235 ;normalize eax\n"
		for h in result[-3:]:
			buffer+="sub eax,"+hex(h)+"\n"
		buffer+="push eax\n\n"
print(Fore.WHITE+buffer)
if args.file:
	asmfile=open(args.file,"w")
	asmfile.write(buffer)
	asmfile.close()
