#ifndef RC4_H
#define RC4_H

using namespace std;

class RC4 {
public:
    RC4() {};

    void setKey(char *keyData, int keyDataLen) {
        int i, j;
        for (i = 0; i < 256; ++i) S[i] = (unsigned char) i;
        for (i = j = 0; i < 256; ++i) {
            j = (j + S[i] + ((unsigned char) keyData[i % keyDataLen])) & 0xff;
            swap(S[i], S[j]);
        }
        for (i = 0; i < 256; ++i) oS[i] = S[i];
    };

    void run(char *data, int dataLen) {
        clear();
        int i, j, t;
        for (i = j = 0; i < dataLen; ++i) {
            int ii = (i + 1) & 0xff;
            j = (j + S[ii]) & 0xff;
            swap(S[ii], S[j]);
            t = (S[ii] + S[j]) & 0xff;
            data[i] ^= S[t];
        }
    };

//    void run(char *data, int st, int en) {
//        clear();
//        int i, j, t;
//        for (i = j = 0; i < en-st; ++i) {
//            int ii = (i + 1) & 0xff;
//            j = (j + S[ii]) & 0xff;
//            swap(S[ii], S[j]);
//            t = (S[ii] + S[j]) & 0xff;
//            data[i+st] ^= S[t];
//        }
//    };
protected:
    void clear() {
        for (int i = 0; i < 256; ++i) S[i] = oS[i];
    };
private:
    unsigned char S[256], oS[256];
};

#endif // RC4_H
