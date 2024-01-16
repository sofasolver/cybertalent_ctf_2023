from os import write
from re import L
from PIL import Image
b64a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
fibs = [1,2,3,5,8,13]
data = open("fibonacci_article.bits","r").read().strip()

def typename(typeid):
    if typeid in range(1,4):
        return "Reserved"
    if typeid == 4:
        return "Text"
    if typeid == 5:
        return "Image"
    return "Unknown"

def extend_fibs():
    clen = len(fibs)
    while len(fibs) < 2 * clen:
        fibs.append(fibs[-1]+fibs[-2])

def decode_num(num):
    sum = 0
    i = 0
    while num:
        if i >= len(fibs):
            extend_fibs()
        if num & 1:
            sum += fibs[i]
        i += 1
        num >>= 1
    return sum

def to_lsb_num(bit_slice):
    return sum(int(c)*(1<<i) for i, c in enumerate(bit_slice))

bits = "".join(
    "".join(reversed(f"{b64a.index(c):06b}")) for c in data
)

def chop(num=6):
    global bits
    bits = bits[num:]

def chop_num():
    global bits
    idx = bits.find("11")
    bits = bits[idx+2:]

def next_num():
    idx = bits.find("11")
    return decode_num(to_lsb_num(bits[:idx+1]))

while len(fibs) < 100:
    extend_fibs()

goal = ",".join(map(str, [1] + fibs[:99])) + ","

content_length = next_num()
chop_num()
print(typename(next_num()))
chop_num()
length = next_num()
chop_num()

print("Text length:", length)

def print_conjecture(rc):
    s = bits
    for k, w in rc.items():
        r = k
        if r == '0':
            r = '!'
        if r == '1':
            r = '%'
        s = s.replace(w, r)

    s = s.replace("1", "_")
    s = s.replace("0", "_")
    s = s.replace("!", "0")
    s = s.replace("%", "1")

    print(s)

def verify_prefix_free(rc):
    for k in rc:
        for c, w in rc.items():
            if c == k:
                continue
            if rc[k].startswith(w) or w.startswith(rc[k]):
                return False
    return True

rc = {
   # "Fibonacci": "10110000010100000101100100001111110011111111111110100",
    "Q" : "000100111101100",
    "Y" : "1100001011100",
    "V" : "101100011001",
    "I" : "111010000",
    "C" : "000110110",
    "S" : "111011001",
    "H" : "0001000111",
    "R" : "0001101111",
    "P" : "1110111110",
    "D" : "0011000111",
    "G" : "1000000011",
    "B" : "1011011010",
    "E" : "110000011",
    "T" : "100101001",
    "L" : "0001101000",
    "M" : "1001011001",
    "O" : "0010101011",
    "A" : "111101010",
    "F" : "101100000",
    "(" : "1101000011",
    ")" : "1011100000",
    "=" : "110100101111",
    "0" : "100001011", 
    "1" : "100100010", 
    "2" : "101110011",
    "3" : "0010101101",
    "4" : "1011101100",
    "6" : "00110000001",
    "5" : "1000000110",
    "8" : "11010100100",
    "9" : "1100001100",
    "7" : "00011001101",
    "q" : "11000110010",
    ";" : "10010101011",
    "*" : "0001000110110",
    "'" : "1111010010",
    "-" : "1100011000",
    "+" : "101101011000",
    "/" : "111101011011",
    "^" : "1001001011100",
    "<" : "001100001100011",
    "w" : "1100010",
    "z" : "1101100001",
    "b" : "0001011",
    "r" : "11001",
    "k" : "1101101",
    "x" : "1001000110",
    "l" : "100110",
    "u" : "110111",
    "o" : "00100",
    "n" : "00111",
    "y" : "0010110",
    "f" : "111100",
    "g" : "101011",
    "s" : "01001",
    "a" : "11100",
    "v" : "0001010",
    "c" : "111111",
    "p" : "001101",
    "m" : "100011",
    "U" : "1110100011",
    "d" : "101010",
    "h" : "01000",
    "i" : "10100",
    "t" : "0101",
    "N" : "1001111000",
    "\n": "1111100",
    "\t": "001100000100010",
    "." : "1011110",
    "," : "0010100",
    "e" : "0000",
    " " : "011",
}

def getw(s):
    res = ""
    for c in s:
        res += rc[c]
    return res


code = {val: k for k, val in rc.items()}

def chop_line():
    global bits
    line = ""
    while True:
        found = None
        for cw in code:
            if bits.startswith(cw):
                found = cw
        assert found is not None
        line += code[found]
        bits = bits[len(found):]
        if code[found] == "\n":
            break
    return line

def chop_word():
    global bits
    word = ""
    while True:
        found = None
        for cw in code:
            if bits.startswith(cw):
                found = cw
        assert found is not None
        word += code[found]
        bits = bits[len(found):]
        if code[found] == " ":
            break
    return word

def get_first_char():
    for cw in code:
        if bits.startswith(cw):
            return code[cw]
    return None


def chop_char():
    global bits
    fc = get_first_char()
    assert fc is not None
    cw = rc[fc]
    bits = bits[len(cw):]
    return fc


def is_prefix(s):
    for cw in code:
        if s.startswith(cw) or cw.startswith(s):
            return True
    return False

assert verify_prefix_free(rc)

for _ in range(30):
    print(chop_line(), end="")

for _ in range(0):
    print(chop_word(), end="")

for _ in range(4):
    print(chop_char(), end="")

print("{", end="") #}

#FLAG{................................}

# 15 here was just guess and check
bits = bits[15:]

for _ in range(32):
    print(chop_char(), end="")

print("}")
