import os
import sys

__author__ = 'circasee'
__description__ = 'Simple rolling XOR encoder'

#############################################################################
def main(argv, argc):
    src = argv[1] if argc > 1 else None
    dst = 'payload.dll'
    hexdump = lambda s: '{}    {}'.format(
        ' '.join(map(lambda i: '{:02x}'.format(i), s)),
        ''.join(map(lambda i: chr(i) if i > 0x1f and i < 0x7f else '.', s))
    )
    
    if not src:
        print 'Specify a source file.'
        sys.exit(1)
    if not os.path.isfile(src):
        print 'Source is not a file.'
        sys.exit(2)
    
    print 'src =', src
    print 'dst =', dst
    print
    
    with open(src, 'rb', 0) as f:
        data = bytearray(f.read())

    print 'Before'
    print '------'
    print hexdump(data[0:16]) + '\n...\n'
    
    k = data[0]
    for i in xrange(1, len(data)):
        data[i] ^= k
        k = data[i]

    print 'After'
    print '-----'
    print hexdump(data[0:16]) + '\n...\n'
    
    
    with open(dst, 'wb', 0) as f:
        f.write(str(data))
        f.flush()

#############################################################################
if __name__ == '__main__':
    main(sys.argv, len(sys.argv))
#EOF