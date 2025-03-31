//
// Created by Administrator on 2023/3/19.
//

#ifndef APP_DEFENDER_LIB_UTILS_H
#define APP_DEFENDER_LIB_UTILS_H

#include <fstream>
#include <iostream>
using namespace std;

class Utils {
public:
    static char char2hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        } else if (c >= 'a' && c <= 'f') {
            return (int) (c - 'a') + 10;
        } else if (c >= 'A' && c <= 'F') {
            return (int) (c - 'A') + 10;
        } else {
            cerr << "given char is not in hex range." << endl;
            return 0;
        }
    }

    static void carraycopy(char *a, char *b, int len) {
        for (int i = 0; i < len; ++i) {
            b[i] = a[i];
        }
    }

    static char *string2carray(string data) {
        int len = data.length() / 2;
        char *ret = new char[len+1];
        for (int i = 0; i < len; ++i) {
            ret[i] = (char) char2hex(data[i * 2]) * 16 + char2hex(data[i * 2 + 1]);
        }
        return ret;
    }

    static char hex2char(unsigned char b) {
        if (b < 10) {
            return b + '0';
        } else {
            return b - 10 + 'a';
        }
    }

    static string carray2string(char *data, int len) {
        string ret;
        for (int i = 0; i < len; ++i) {
            ret += hex2char(((unsigned char) data[i]) / 16);
            ret += hex2char(((unsigned char) data[i]) % 16);
        }
        return ret;
    }


};


#endif //APP_DEFENDER_LIB_UTILS_H
