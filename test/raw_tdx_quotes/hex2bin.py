import binascii

with open('quote_event.hex', 'r') as f:
    hexdata = f.read().strip()

bindata = binascii.unhexlify(hexdata)

with open('output.bin', 'wb') as f:
    f.write(bindata) 