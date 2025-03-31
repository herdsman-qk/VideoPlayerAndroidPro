//
// Created by Administrator on 2023/3/3.
//

#include "../header/Log.hpp"
#include <cstdarg>
#include <android/log.h>

void Log::error(const char *pMessage, ...) {
    va_list varArgs;
    va_start(varArgs, pMessage);
    __android_log_vprint(ANDROID_LOG_ERROR, "KEE_LOG", pMessage,
                         varArgs);
    __android_log_print(ANDROID_LOG_ERROR, "KEE_LOG", "\n");
    va_end(varArgs);
}

void Log::warn(const char *pMessage, ...) {
    va_list varArgs;
    va_start(varArgs, pMessage);
    __android_log_vprint(ANDROID_LOG_WARN, "KEE_LOG", pMessage,
                         varArgs);
    __android_log_print(ANDROID_LOG_WARN, "KEE_LOG", "\n");
    va_end(varArgs);
}

void Log::info(const char *pMessage, ...) {
    va_list varArgs;
    va_start(varArgs, pMessage);
    __android_log_vprint(ANDROID_LOG_INFO, "KEE_LOG", pMessage,
                         varArgs);
    __android_log_print(ANDROID_LOG_INFO, "KEE_LOG", "\n");
    va_end(varArgs);
}

void Log::debug(const char *pMessage, ...) {
    va_list varArgs;
    va_start(varArgs, pMessage);
    __android_log_vprint(ANDROID_LOG_DEBUG, "KEE_LOG", pMessage,
                         varArgs);
    __android_log_print(ANDROID_LOG_DEBUG, "KEE_LOG", "\n");
    va_end(varArgs);
}