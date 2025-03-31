cmake_minimum_required(VERSION 3.10.2)

add_library(Main SHARED
        main.cpp
        header/Log.hpp
        source/Log.cpp
        header/Utils.h
        header/rsa_stl.h
        header/des_stl.h
        header/rc4_stl.h
        )

#include_directories(${ANDROID_NDK}/sources/android/native_app_glue )
#add_library(native_app_glue STATIC
#        ${ANDROID_NDK}/sources/android/native_app_glue/android_native_app_glue.c )
find_library(log-lib log)
#find_library(android android )
#find_library(egl-lib EGL )
#find_library(gles-lib GLESv1_CM )
target_link_libraries(Main
        ${log-lib})
#${android} ${egl-lib} ${gles-lib}
#native_app_glue