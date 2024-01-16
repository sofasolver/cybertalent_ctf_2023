from PIL import Image
b64a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
data = open("flag0.bits","r").read().strip()
fibs = [1,2,3,5,8,13]

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


print(next_num())
chop_num()
print(typename(next_num()))
chop_num()
width = next_num()
chop_num()
height = next_num()
chop_num()

bits = bits[:width*height]
print(bits[:401])
print(bits[-401:])

img = Image.new("RGB", (width, height), "black")
pixels = img.load()

ptr = 0
for j in range(height):
    for i in range(width):
        if bits[j * width + i] == '1':
            pixels[i,j] = (255, 255, 255)
        ptr += 1


img.save("flag0.bmp")
