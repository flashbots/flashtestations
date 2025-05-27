import binascii

with open('quote_events.txt', 'r') as f:
    hexdata = f.read().strip()

bindata = binascii.unhexlify(hexdata)

with open('quote.bin', 'wb') as f:
    f.write(bindata) 