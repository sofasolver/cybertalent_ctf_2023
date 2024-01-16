#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using word = uint16_t;

using namespace std;

word l_022a, l_022b, l_022c, l_022d, l_022e;
word l_0226, l_0227, l_0228, l_0229;

word asumxorbcd() {
    return ((l_022b ^ l_022c) ^ l_022d) + l_022a;
}

void rotaddb() {
    l_022a = l_022d;
    l_022d = l_022c;
    l_022c = l_022b;
    l_022b = l_022e + l_022b;
}

word lro(word x, int n) {
    for (int i = 0; i < n; ++i) {
        word bt = (x >> 15)&1;
        x = (x << 1) | bt;
    }
    return x;
}

word l_01e4() {
    return l_022a + ((l_022b | (~l_022d)) ^ l_022c);
}

word l_01f6() {
    return l_022a + ((l_022b & l_022d) | (l_022c & (~l_022d)));
}

word l_020e() {
    return l_022a + ((l_022b & l_022c) | (l_022d & (~l_022b)));
}

void transf(word a, word b, word c, word d) {
    l_0226 = a;
    l_0227 = b;
    l_0228 = c;
    l_0229 = d;

    l_022a = 0x0123;
    l_022b = 0x4567;
    l_022c = 0x89ab;
    l_022d = 0xcdef;

    word alx = asumxorbcd();
    l_022e = alx+l_0226;

    rotaddb();

    alx = asumxorbcd();
    word aly = l_0227;
    l_022e = lro(alx+aly, 3);

    rotaddb();

    alx = asumxorbcd();
    aly = l_0228;

    l_022e = lro(alx+aly, 6);

    rotaddb();
    alx = asumxorbcd();
    aly = l_0229;
    l_022e = lro(alx+aly, 1);

    rotaddb();

    alx = l_01e4();
    aly = l_0226;

    l_022e = lro(alx+aly, 4);

    rotaddb();

    alx = l_01e4();
    aly = l_0227;

    l_022e = lro(alx+aly, 7);

    rotaddb();

    alx = l_01e4();
    aly = l_0228;

    l_022e = lro(alx+aly, 2);

    rotaddb();

    alx = l_01e4();
    aly = l_0229;

    l_022e = lro(alx+aly, 5);

    rotaddb();

    alx = l_01f6();
    aly = l_0226;
    l_022e = alx+aly;

    rotaddb();

    alx = l_01f6();
    aly = l_0227;
    l_022e = lro(alx+aly, 5);

    rotaddb();
    alx = l_01f6();
    aly = l_0228;

    l_022e = lro(alx+aly, 2);

    rotaddb();

    alx = l_01f6();
    aly = l_0229;

    l_022e = lro(alx+aly, 7);

    rotaddb();

    alx = l_020e();
    aly = l_0226;

    l_022e = lro(alx+aly, 4);

    rotaddb();

    alx = l_020e();
    aly = l_0227;

    l_022e = lro(alx+aly, 1);

    rotaddb();

    alx = l_020e();
    aly = l_0228;

    l_022e = lro(alx+aly, 6);

    rotaddb();

    alx = l_020e();
    aly = l_0229;

    l_022e = lro(alx+aly, 3);

    rotaddb();
}

std::vector<word> crypt(const string& pass) {
    vector<word> pasw;
    for (auto c : pass)pasw.push_back((word)c);

    l_022a = (pasw[0] << 8) | pasw[1];
    l_022b = (pasw[2] << 8) | pasw[3];
    l_022c = (pasw[4] << 8) | pasw[5];
    l_022d = (pasw[6] << 8) | pasw[7];

    vector<word> l_00ac = {
        0xf781,
        0x53b0,
        0x9eaa,
        0xc15b,
        0x5543,
        0xd3eb,
        0x2377,
        0xbb85,
        0xa907,
        0x7fd3,
        0xdd00,
        0x4910,
        0xd03f,
        0x9f48,
        0x36b3,
        0xe02e
    };

    for (int i = 0; i < 4; ++i) {
        transf(l_022a, l_022b, l_022c, l_022d);
        l_00ac[4*i+0] ^= l_022a;
        l_00ac[4*i+1] ^= l_022b;
        l_00ac[4*i+2] ^= l_022c;
        l_00ac[4*i+3] ^= l_022d;
    }

    return l_00ac;
}

bool check(const std::vector<word>& res) {
    return (
        res[0] == (word)'F' &&
        res[1] == (word)'L' &&
        res[2] == (word)'A' &&
        res[3] == (word)'G'
    ) || (
        res[0] == (word)'f' &&
        res[1] == (word)'l' &&
        res[2] == (word)'a' && 
        res[3] == (word)'g');
}

int main() {
    string pass = "AAAAAAAA";

    while (true) {
        auto res = crypt(pass);


        if (check(res)) {
            cout << "Found password: " << pass << endl;
            break;
        }

        bool fin = 0;
        for (int i = 7; i >= 0; --i) {
            pass[i] += 1;
            if (pass[i] > 'Z') {
                if (i == 0) {
                    fin = true;
                    break;
                }
                pass[i] = 'A';
            } else break;
        }
        if (fin)break;
    }
}
