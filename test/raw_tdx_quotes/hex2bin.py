import binascii

with open('quote.output', 'r') as f:
    hexdata = f.read().strip()

bindata = binascii.unhexlify(hexdata)

with open('quote.raw.output', 'wb') as f:
    f.write(bindata) 