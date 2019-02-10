import binascii, sys
import r2pipe

res = ""

for byte in reversed(binascii.unhexlify(sys.argv[1])):
  bits = bin(ord(byte))[2:].zfill(8)
  res += bits[0:4]
  res += " "
  res += bits[4:]
  res += " | "

print res

r = r2pipe.open('/dev/null')
r.cmd("e asm.arch=xtensa")
print("DISASS")
print r.cmd("pad "+sys.argv[1])
print("ESIL")
print r.cmd("pade "+sys.argv[1])
