from collections import deque

goal = "00000111110000100100011000011100101110011111001100101010010001000011010100001000011110011111101110000011000110111111111001101111011100011001000000011100110000101011011101111000001101000111111111100001000010001110000011111101011000011111100000101111111011100010011011100011111111101001000011100000000101110100000010000100111110110000011110001011111111101011111100011110001000111100001111010100011111100"
goal = [ord(c) - ord('0') for c in goal]

# (start, end, iteration) . Distance between nums in interval: 3**iteration
M = 1<<64
mask = M - 1
q = deque()
q.append((1, M-1, 0))

for _ in range(500000000):
    s, t, i = q.popleft()
    if i == 40:
        q.appendleft((s,t,i))
        break

    sv = 3 * s
    lo = (M>>1)*(sv//(M>>1))
    hi  = lo + (M>>1)
    p3 = 3**i

    k = (hi - sv - 1) // (3*p3)
    tv = s + k * p3
    if tv < t:
        q.appendleft((tv+p3, t, i))
    else:
        tv = t

    bt = ((sv & mask) >> 63)&1
    if bt == goal[i]:
        q.append((sv%M, (3*tv)%M, i+1))


tot = 0
neq = 0
for s, t, i in q:
    for num in range(s, t+1, 3**i):
        print(f"{num} {i}")
    cnt = (t - s)//(3**i) + 1
    tot += cnt

