
# utility functions for dealing with primes

from Crypto.Util import number
from util import bit_length, inflate_long


def generate_prime(bits, randpool):
    hbyte_mask = pow(2, bits % 8) - 1
    while 1:
        # loop catches the case where we increment n into a higher bit-range
        x = randpool.get_bytes((bits+7) // 8)
        if hbyte_mask > 0:
            x = chr(ord(x[0]) & hbyte_mask) + x[1:]
        n = inflate_long(x, 1)
        n |= 1
        n |= (1 << (bits - 1))
        while not number.isPrime(n):
            n += 2
        if bit_length(n) == bits:
            return n

def roll_random(randpool, n):
    "returns a random # from 0 to N-1"
    bits = bit_length(n-1)
    bytes = (bits + 7) // 8
    hbyte_mask = pow(2, bits % 8) - 1

    # so here's the plan:
    # we fetch as many random bits as we'd need to fit N-1, and if the
    # generated number is >= N, we try again.  in the worst case (N-1 is a
    # power of 2), we have slightly better than 50% odds of getting one that
    # fits, so i can't guarantee that this loop will ever finish, but the odds
    # of it looping forever should be infinitesimal.
    while 1:
        x = randpool.get_bytes(bytes)
        if hbyte_mask > 0:
            x = chr(ord(x[0]) & hbyte_mask) + x[1:]
        num = inflate_long(x, 1)
        if num < n:
            return num


class ModulusPack (object):
    """
    convenience object for holding the contents of the /etc/ssh/moduli file,
    on systems that have such a file.
    """

    def __init__(self, randpool):
        # pack is a hash of: bits -> [ (generator, modulus) ... ]
        self.pack = {}
        self.discarded = []
        self.randpool = randpool

    def _parse_modulus(self, line):
        timestamp, type, tests, tries, size, generator, modulus = line.split()
        type = int(type)
        tests = int(tests)
        tries = int(tries)
        size = int(size)
        generator = int(generator)
        modulus = long(modulus, 16)

        # weed out primes that aren't at least:
        # type 2 (meets basic structural requirements)
        # test 4 (more than just a small-prime sieve)
        # tries < 100 if test & 4 (at least 100 tries of miller-rabin)
        if (type < 2) or (tests < 4) or ((tests & 4) and (tests < 8) and (tries < 100)):
            self.discarded.append((modulus, 'does not meet basic requirements'))
            return
        if generator == 0:
            generator = 2

        # there's a bug in the ssh "moduli" file (yeah, i know: shock! dismay!
        # call cnn!) where it understates the bit lengths of these primes by 1.
        # this is okay.
        bl = bit_length(modulus)
        if (bl != size) and (bl != size + 1):
            self.discarded.append((modulus, 'incorrectly reported bit length %d' % size))
            return
        if not self.pack.has_key(bl):
            self.pack[bl] = []
        self.pack[bl].append((generator, modulus))

    def read_file(self, filename):
        """
        @raise IOError: passed from any file operations that fail.
        """
        self.pack = {}
        f = open(filename, 'r')
        for line in f:
            line = line.strip()
            if (len(line) == 0) or (line[0] == '#'):
                continue
            try:
                self._parse_modulus(line)
            except:
                continue
        f.close()

    def get_modulus(self, min, prefer, max):
        bitsizes = self.pack.keys()
        bitsizes.sort()
        if len(bitsizes) == 0:
            raise SSHException('no moduli available')
        good = -1
        # find nearest bitsize >= preferred
        for b in bitsizes:
            if (b >= prefer) and (b < max) and ((b < good) or (good == -1)):
                good = b
        # if that failed, find greatest bitsize >= min
        if good == -1:
            for b in bitsizes:
                if (b >= min) and (b < max) and  (b > good):
                    good = b
        if good == -1:
            # their entire (min, max) range has no intersection with our range.
            # if their range is below ours, pick the smallest.  otherwise pick
            # the largest.  it'll be out of their range requirement either way,
            # but we'll be sending them the closest one we have.
            good = bitsizes[0]
            if min > good:
                good = bitsizes[-1]
        # now pick a random modulus of this bitsize
        n = roll_random(self.randpool, len(self.pack[good]))
        return self.pack[good][n]

