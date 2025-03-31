package com.dev.kee.video;

public class KeEVideoUtils {
    static {
        System.loadLibrary("Main");
    }

    public static native byte[] decrypt(byte[] in, int len);

    public static native VideoItem parseFile(String path);

    public static native byte[] getThumb(String path, int len);
}
