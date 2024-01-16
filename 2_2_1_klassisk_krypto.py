from itertools import count, chain, product
from collections.abc import Iterable
from typing import Optional

Square = dict[str, tuple[int,int]]

def pat_match(pat: str, s: str) -> bool:
    if len(pat) != len(s):
        return False

    mapping = dict()

    for a, b in zip(pat, s):
        if a == "-":
            continue

        if a not in mapping:
            mapping[a] = b
        elif mapping[a] != b:
            return False
    return True


def pat_search(ciph: str, pat: str) -> list[int]:
    pat = pat.replace(" ", "")

    ret = []
    for i in range(0, len(ciph), 2):
        sub = ciph[i:i+len(pat)]
        if len(sub) < len(pat):
            break

        if pat_match(pat, sub):
            ret.append(i)
    return ret

class FourSquare:
    @classmethod
    def with_plaintext_squares(cls):
        four_square = cls()

        ALPHABET = "abcdefghijklmnoprstuvwxyz"
        
        for i, ch in enumerate(reversed(ALPHABET)):
            dr, dc = i // 5, i % 5
            four_square.top_lft[ch] = (-dr, -1-dc)

        for i, ch in enumerate(ALPHABET):
            dr, dc = i // 5, i % 5
            four_square.bot_rgt[ch] = (1+dr, dc)
        
        return four_square


    def __init__(self):
        self.top_lft: Square = {}
        self.top_rgt: Square = {}
        self.bot_lft: Square = {}
        self.bot_rgt: Square = {}

    def ciphertext_lookup(self, ciphertext_digraph: str) -> tuple[Optional[str], Optional[str]]:
        tr_pos = self.top_rgt.get(ciphertext_digraph[0])
        bl_pos = self.bot_lft.get(ciphertext_digraph[1])

        if tr_pos is None or bl_pos is None:
            return (None, None)

        tl_pos = (tr_pos[0], bl_pos[1])
        br_pos = (bl_pos[0], tr_pos[1])

        plain_a = None
        plain_b = None

        for k in self.top_lft:
            if self.top_lft[k] == tl_pos:
                plain_a = k
                break

        for k in self.bot_rgt:
            if self.bot_rgt[k] == br_pos:
                plain_b = k
                break

        return (plain_a, plain_b)

    def plaintext_lookup(self, plaintext_digraph: str) -> tuple[Optional[str], Optional[str]]:
        tl_pos = self.top_lft.get(plaintext_digraph[0])
        br_pos = self.bot_rgt.get(plaintext_digraph[1])

        if tl_pos is None or br_pos is None:
            return (None, None)

        tr_pos = (tl_pos[0], br_pos[1])
        bl_pos = (br_pos[0], tl_pos[1])

        ciph_a = None
        ciph_b = None

        for k in self.top_rgt:
            if self.top_rgt[k] == tr_pos:
                ciph_a = k
                break

        for k in self.bot_lft:
            if self.bot_lft[k] == bl_pos:
                ciph_b = k
                break

        return (ciph_a, ciph_b)


        
    def assign(self, ciphertext_digraph: str, plaintext_digraph: str) -> bool:
        """
        Tries to fit the supplied digraphs in the four square.
        Performs row or column merging if necessary.
        Returns a boolean indicating success.
        """
        ciph_a, ciph_b = list(ciphertext_digraph)
        plain_a, plain_b = list(plaintext_digraph.lower())

        tl_pos = self.top_lft.get(plain_a)
        tr_pos = self.top_rgt.get(ciph_a)
        bl_pos = self.bot_lft.get(ciph_b)
        br_pos = self.bot_rgt.get(plain_b)

        if tl_pos is None and tr_pos is None:
            top_row = self.get_independent_row(self.top_lft, self.top_rgt, count(0, -1))
        elif tl_pos is None:
            assert tr_pos is not None
            top_row = tr_pos[0]
        elif tr_pos is None:
            top_row = tl_pos[0]
        elif tl_pos[0] == tr_pos[0]:
            top_row = tl_pos[0]
        else:
            top_row = self.merge_rows(self.top_lft, self.top_rgt, tl_pos[0], tr_pos[0])
            if top_row is None:
                return False
        
        if bl_pos is None and br_pos is None:
            bot_row = self.get_independent_row(self.bot_lft, self.bot_rgt, count(1, 1))
        elif bl_pos is None:
            assert br_pos is not None
            bot_row = br_pos[0]
        elif br_pos is None:
            bot_row = bl_pos[0]
        elif bl_pos[0] == br_pos[0]:
            bot_row = bl_pos[0]
        else:
            bot_row = self.merge_rows(self.bot_lft, self.bot_rgt, bl_pos[0], br_pos[0])
            if bot_row is None:
                return False

        if tl_pos is None and bl_pos is None:
            lft_col = self.get_independent_col(self.top_lft, self.bot_lft, count(-1,-1))
        elif tl_pos is None:
            assert bl_pos is not None
            lft_col = bl_pos[1]
        elif bl_pos is None:
            lft_col = tl_pos[1]
        elif tl_pos[1] == bl_pos[1]:
            lft_col = tl_pos[1]
        else:
            lft_col = self.merge_cols(self.top_lft, self.bot_lft, tl_pos[1], bl_pos[1])
            if lft_col is None:
                return False

        if tr_pos is None and br_pos is None:
            rgt_col = self.get_independent_col(self.top_rgt, self.bot_rgt, count(0, 1))
        elif tr_pos is None:
            assert br_pos is not None
            rgt_col = br_pos[1]
        elif br_pos is None:
            rgt_col = tr_pos[1]
        elif tr_pos[1] == br_pos[1]:
            rgt_col = tr_pos[1]
        else:
            rgt_col = self.merge_cols(self.top_rgt, self.bot_rgt, tr_pos[1], br_pos[1])
            if rgt_col is None:
                return False

        # Hopefully this is not an issue now:)
        self.top_lft[plain_a] = (top_row, lft_col)
        self.top_rgt[ciph_a]  = (top_row, rgt_col)
        self.bot_lft[ciph_b]  = (bot_row, lft_col)
        self.bot_rgt[plain_b] = (bot_row, rgt_col)

        if not all(map(self.verify_unique, 
            [self.top_lft, self.top_rgt, self.bot_lft, self.bot_rgt])):
            return False

        return True

    def verify_unique(self, square: Square):
        visited: set[tuple[int,int]] = set()

        for pos in square.values():
            if pos in visited:
                return False
            visited.add(pos)

        return True

    def get_independent_row(self, square_a: Square, square_b: Square, row_space: Iterable[int]) -> int:
        """
        Find a number in row_space which is not the row of any element from square_a nor square_b
        """
        used_rows = set(chain(
            (r for r, _ in square_a.values()), 
            (r for r, _ in square_b.values())
        ))

        for row in row_space:
            if row not in used_rows:
                return row

        assert False, "Unreachable code"

    def get_independent_col(self, square_a: Square, square_b: Square, col_space: Iterable[int]) -> int:
        """
        Find a number in col_space which is not the col of any element from square_a nor square_b
        """
        used_cols = set(chain(
            (c for _, c in square_a.values()), 
            (c for _, c in square_b.values())
        ))

        for col in col_space:
            if col not in used_cols:
                return col 

        assert False, "Unreachable code"

    def merge_rows(self, square_a: Square, square_b: Square, from_row: int, to_row: int) -> Optional[int]:
        # Save existing positions to check for collisions
        square_a_positions = set(square_a.values())
        square_b_positions = set(square_b.values())

        for r, c in square_a.values():
            if r != from_row:
                continue

            if (to_row, c) in square_a_positions:
                # Would create a collision
                return None

        for r, c in square_b.values():
            if r != from_row:
                continue

            if (to_row, c) in square_b_positions:
                return None

        for k in square_a:
            if square_a[k][0] != from_row:
                continue
            square_a[k] = (to_row, square_a[k][1])

        for k in square_b:
            if square_b[k][0] != from_row:
                continue
            square_b[k] = (to_row, square_b[k][1])

        return to_row

    def merge_cols(self, square_a: Square, square_b: Square, from_col: int, to_col: int) -> Optional[int]:
        # Save existing positions to check for collisions
        square_a_positions = set(square_a.values())
        square_b_positions = set(square_b.values())

        for r, c in square_a.values():
            if c != from_col:
                continue

            if (r, to_col) in square_a_positions:
                # Would create a collision
                return None

        for r, c in square_b.values():
            if c != from_col:
                continue

            if (r, to_col) in square_b_positions:
                return None

        for k in square_a:
            if square_a[k][1] != from_col:
                continue
            square_a[k] = (square_a[k][0], to_col)

        for k in square_b:
            if square_b[k][1] != from_col:
                continue
            square_b[k] = (square_b[k][0], to_col)

        return to_col
    def decrypt(self, ciphertext: str) -> str:
        plain = ["_"] * len(ciphertext)
        for i in range(0, len(ciphertext), 2):
            dig = ciphertext[i:i+2]

            plain_dig = self.ciphertext_lookup(dig)
            
            if plain_dig[0] is not None:
                plain[i] = plain_dig[0]

            if plain_dig[1] is not None:
                plain[i+1] = plain_dig[1]

        return "".join(plain)

    def encrypt(self, plaintext: str) -> str:
        ciph = ["_"] * len(plaintext)
        for i in range(0, len(plaintext), 2):
            dig = plaintext[i:i+2]

            ciph_dig = self.plaintext_lookup(dig)

            if ciph_dig[0] is not None:
                ciph[i] = ciph_dig[0]

            if ciph_dig[1] is not None:
                ciph[i+1] = ciph_dig[1]

        return "".join(ciph)

    def debug_print(self):
        pos_to_char: dict[tuple[int,int], str] = dict()

        maxr = -10**9
        minr = 10**9
        maxc = -10**9
        minc = 10**9

        for item in chain(
            self.top_lft.items(),
            self.top_rgt.items(),
            self.bot_lft.items(),
            self.bot_rgt.items()
        ):
            r, c = item[1]
            pos_to_char[(r, c)] = item[0]

            maxr = max(maxr, r)
            maxc = max(maxc, c)
            minr = min(minr, r)
            minc = min(minc, c)

        buf = [[" "] * (maxc - minc + 1) for _ in range(maxr - minr + 1)]

        for r, c in pos_to_char:
            adj_r = r - minr
            adj_c = c - minc

            buf[adj_r][adj_c] = pos_to_char[(r, c)]

        print("\n".join("".join(row) for row in buf))



def split_digraphs(text) -> list[str]:
    return [a+b for a,b in zip(text[::2], text[1::2])]

def build_general_four_square(ciphertext: str, crib: str, crib_pos = 0, silent = False, four_square: Optional[FourSquare] = None) -> bool:
    if crib_pos % 2 == 1:
        crib_pos += 1
        crib = crib[1:]

    crib = crib.lower()
    crib = crib.replace(" ", "")
    ciphertext = ciphertext.replace(" ", "")

    if four_square is None:
        four_square = FourSquare()

    for ciph_dig, crib_dig in zip(
        split_digraphs(ciphertext[crib_pos:]),
        split_digraphs(crib)
    ):
        if not four_square.assign(ciph_dig, crib_dig):
            if not silent:
                print(f"Failed on digraphs {ciph_dig} <-> {crib_dig}")
            return False

    return True

def partial_decrypt(ciphertext: str, crib: str, crib_pos: int = 0, silent = False, four_square: Optional[FourSquare] = None):
    if four_square is None:
        four_square = FourSquare()

    if not build_general_four_square(ciphertext, crib, crib_pos, silent, four_square):
        return False

    plain = four_square.decrypt(ciphertext)
    if not silent:
        print(plain)

    four_square.debug_print()


def partial_multi_decrypt(ciphertext: str, cribs: list[tuple[str, int]], silent: bool = False, four_square: Optional[FourSquare] = None):
    if four_square is None:
        four_square = FourSquare()

    for crib, crib_pos in cribs:
        if not build_general_four_square(ciphertext, crib, crib_pos, silent, four_square):
            if not silent:
                print("Failed for crib: " + crib)
            return None

    res = four_square.decrypt(ciphertext)
    if not silent:
        print(res)
    #four_square.debug_print()
    return res

full_cipher = "ENRWJZBTWEJKFFHBGKJNVSFSVUICENKTVBEOVKWMUGKZXMKZKVROOLVJLYVUHIHGJKHBVGVJXOEIKOJKTSEZYOBJMWSBEVRDTSBUSOTUWEUIZILXTSHBWJVTKXVJKMYVTIRCIEXZMXEYWRENHEXIEXHESXBTEOZITFVOVJSPKONXWLMKFVEOYZFKMWJYNCSVICTIBSEMLCLYLYLCMJWFWCPCRIZYMKEOYXJDHIKJKBWCPCHIKJSBNVXEWOOBKUMOHIKJEZNMGMOBKUMOOBKUMOZORGJOWLKOBIFVYMGSLRICTILRICTIVSPKXWJCWLFKJOWLKOLHICTITLXMJCBEJOWLKOXHHTLDKVWBRWWLFKHIKJKBWCPCHIKJSNUIMONMGMCCFIGX"

fs = FourSquare.with_plaintext_squares()
res = partial_multi_decrypt(full_cipher, [
    ("allofusintheofficeforclassicalcipherscongratulateyou", 0),
    ("passing", 56),
    ("thurdle", 70),
    ("fewmore", 91),
    ("youare", 108),
    ("obablyal", 136),
    ("thavet", 164),
    ("victord", 191),
    ("ianovember", 214),
    ("indiaindia", 228),
    ("indiafoxtro", 238),
    ("foxtrot", 243),
    ("victor", 250),
    ("juliett", 282),
    ("november", 289),
    ("ettvic", 324),
    ("kilo", 354),
    ("yankee", 386),
], silent=False, four_square=fs)

print()
fs.debug_print()
print()
