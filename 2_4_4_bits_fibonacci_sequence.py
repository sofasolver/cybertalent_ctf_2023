from os import write
from PIL import Image
b64a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
fibs = [1,2,3,5,8,13]
data = open("fibonacci_sequence.bits","r").read().strip()

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

print("Number of '1's:", goal.count("1"))
for i in range(1,20):
    cw = bits[:i]
    #print("Code", cw, "count", bits.count(cw))

# We sould have 139 1-s

code = dict()
rc = dict()
code['100100010'] = '1'
rc['1'] = '100100010'
print("Guessing code for '1':", rc['1'])

rc[','] = bits[len(rc['1']):bits.find(rc['1'], 1)]
code[rc[',']] = ','
print("Yielding code for ',':", rc[','])

n1 = bits.find(rc['1'],1)
nc = bits.find(rc[','], n1)
nc2 = bits.find(rc[','], nc+1)

rc['2'] = bits[nc+len(rc[',']):nc2]
code[rc['2']] = '2'
print("Guessing code for '2':", rc['2'])

nc = nc2
nc2 = bits.find(rc[','], nc+1)
rc['3'] = bits[nc+7:nc2]
code[rc['3']] = '3'
print("Guessing code for '3':", rc['3'])

nc = nc2
nc2 = bits.find(rc[','], nc+1)
rc['5'] = bits[nc+7:nc2]
code[rc['5']] = '5'
print("Guessing code for '5':", rc['5'])

#sanity = "".join(map(lambda c: rc[c], "1,1,2,3,5"))
#print(sanity)
#print(bits[:len(sanity)])

nc = nc2
nc2 = bits.find(rc[','], nc+1)
rc['8'] = bits[nc+7:nc2]
code[rc['8']] = '8'
print("Guessing code for '8':", rc['8'])

nc = nc2
nc2 = bits.find(rc[','], nc+1)
assert bits[nc+7:nc2] == rc['1']+rc['3']

nc = nc2
nc2 = bits.find(rc[','], nc+1)
assert bits[nc+7:nc2] == rc['2']+rc['1']

nc = nc2
nc2 = bits.find(rc[','], nc+1)

rc['4'] = bits[nc+len(rc[','])+len(rc['3']):nc2]
code[rc['4']] = '4'
print("Guessing code for '4':", rc['4'])

nc = nc2
nc2 = bits.find(rc[','], nc+1)
assert bits[nc+7:nc2] == rc['5']+rc['5']

nc = nc2
nc2 = bits.find(rc[','], nc+1)
rc['9'] = bits[nc+len(rc[','])+len(rc['8']):nc2]
code[rc['9']] = '9'
print("Guessing code for '9':", rc['9'])

nc = nc2
nc2 = bits.find(rc[','], nc+1)
assert bits[nc+7:nc2] == rc['1']+rc['4']+rc['4']

nc = nc2
nc2 = bits.find(rc[','], nc+1)
assert bits[nc+7:nc2] == rc['2'] + rc['3'] + rc['3']

nc = nc2
nc2 = bits.find(rc[','], nc+1)
c77 = bits[nc+len(rc[','])+len(rc['3']):nc2]
rc['7'] = c77[:len(c77)//2]
code[rc['7']] = '7'
print("Guessing code for '7':", rc['7'])

nc = nc2
nc2 = bits.find(rc[','], nc+1)

rc['6'], rc['0'] = bits[nc+7:nc2].split(rc['1'])
code[rc['6']] = '6'
code[rc['0']] = '0'

print("Guessing code for '6':", rc['6'])
print("Guessing code for '0':", rc['0'])

# Now we have our code:))

res = ""

while True:
    found = None
    for cw, val in code.items():
        if bits.startswith(cw):
            found = cw
    if found is None:
        break
    res += code[found]
    bits = bits[len(found):]

assert res == goal
print("Test ok, we found the code")

for k in ",0123456789":
    print(k, ":", rc[k])
