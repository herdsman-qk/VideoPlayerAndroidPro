#include <jni.h>
#include <string>
#include "header/Log.hpp"

#include "header/Utils.h"
#include "header/rc4_stl.h"

using namespace std;
#define JNI_APP_METHOD(RETURN, METHOD) extern "C" JNIEXPORT RETURN JNICALL Java_com_dev_kee_video_KeEVideoUtils_##METHOD

struct KVFH { // struct for KeE Video File Header
    char uid[8];
    unsigned char rsaPubKey[128];
    int id;
    char title[512];
    char subtitle[512];
    char category[256];
    char pubCode[256];
    char allowCode[256];
    char info1[104];
    int duration; //unit: sec
    int size; //unit: MB

    int thumbLen;

    KVFH() {}

};

JNI_APP_METHOD(jbyteArray, getThumb)(JNIEnv *env, jclass, jstring path, int len) {
    FILE *file = fopen(env->GetStringUTFChars(path, 0), "rb");

    int hSize = sizeof(KVFH);
    fseek(file, hSize, 0);
    char *data = (char *) malloc(len);
    fread(data, 1u, len, file);
    jbyteArray ret = env->NewByteArray(len);
    env->SetByteArrayRegion(ret, 0, len, (jbyte *) data);
    fclose(file);
    free(data);

    return ret;
}

JNI_APP_METHOD(jobject, parseFile)(JNIEnv *env, jclass, jstring path) {

    FILE *file = fopen(env->GetStringUTFChars(path, 0), "rb");

    int hSize = sizeof(KVFH);
    KVFH *h = new KVFH();
    memset(reinterpret_cast<char *>(h), 0, hSize);
    char *hData = (char *) malloc(hSize);
    fread(hData, 1u, hSize, file);
    for (int i = 0; i < hSize; ++i) {
        hData[i] ^= 0x21;
    }

    Utils::carraycopy(hData, reinterpret_cast<char *>(h), hSize);

    fclose(file);
    free(h);
    free(hData);

    jclass cls_VideoItem = env->FindClass("com/dev/kee/video/VideoItem");
    jmethodID mth_init_VideoItem = env->GetMethodID(cls_VideoItem, "<init>", "()V");
    jobject item = env->NewObject(cls_VideoItem, mth_init_VideoItem);

    env->SetObjectField(item, env->GetFieldID(cls_VideoItem, "uid", "Ljava/lang/String;"), env->NewStringUTF(Utils::carray2string(h->uid, 8).c_str()));
    env->SetObjectField(item, env->GetFieldID(cls_VideoItem, "rsaPubKey", "Ljava/lang/String;"), env->NewStringUTF(Utils::carray2string(reinterpret_cast<char *>(h->rsaPubKey), 128).c_str()));
    env->SetIntField(item, env->GetFieldID(cls_VideoItem, "size", "I"), h->size);
    env->SetIntField(item, env->GetFieldID(cls_VideoItem, "thumbLen", "I"), h->thumbLen);
    env->SetIntField(item, env->GetFieldID(cls_VideoItem, "duration", "I"), h->duration);
    env->SetObjectField(item, env->GetFieldID(cls_VideoItem, "title", "Ljava/lang/String;"), env->NewStringUTF(h->title));

    return item;
}

JNI_APP_METHOD(void, setKey)(JNIEnv *env, jclass, jstring in, int len) {
}

JNI_APP_METHOD(jbyteArray, decrypt)(JNIEnv *env, jclass, jbyteArray in, jint len) {
    RC4 *rc4 = new RC4();
    char *temp = (char *) env->GetByteArrayElements(in, 0);

    string s = Utils::carray2string(reinterpret_cast<char *>(temp), len);

    rc4->setKey(Utils::string2carray(
            "d0657d2047da84ec3d03db89e174525beec059cb7f8dbde3f11eb3ed6a94690533d07ca575a47710d027a1730c2928e7d630120da6e6f32f94f6de473c4110ec5bf72fcb07f4e5f295885c74eacefe0856287076b6c8df89d238a3f9eefeded430a99e026105abb17b06205ceaf96747bead22267221768a28ba34300a946407"),
                128);
    char tbuf[0x800];
    int ct = 0;
    for (int i = 0; i < len; ++i) {
        tbuf[ct] = temp[i];
        ct++;
        if (ct == 0x800) {
            rc4->run(tbuf, 0x800);
            for (int k = 0; k < ct; ++k) {
                temp[i - ct + k + 1] = tbuf[k];
            }
            ct = 0;
        }
    }

    if (ct > 0) {
        rc4->run(tbuf, 0x800);
        for (int k = 0; k < ct; ++k) {
            temp[len - ct + k] = tbuf[k];
        }
    }

    jbyteArray ret = env->NewByteArray(len);
    env->SetByteArrayRegion(ret, 0, len, (jbyte *) temp);
    return ret;
}
