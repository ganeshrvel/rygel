// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

#pragma once

// Don't include js-config.h, we deal with everything here through forced inclusion
#define js_config_h

#define MOZILLA_UAVERSION "91.0"
#define MOZILLA_VERSION "91.3.0"
#define MOZILLA_VERSION_U 91.3.0
#define MOZJS_MAJOR_VERSION 91
#define MOZJS_MINOR_VERSION 3
#define MOZ_BUILD_APP js
#define MOZ_UPDATE_CHANNEL default
#define RELEASE_OR_BETA 1

#define WASM_SUPPORTS_HUGE_MEMORY
#define JS_CACHEIR_SPEW
#define JS_STRUCTURED_SPEW
#define STATIC_JS_API
#define MOZILLA_CLIENT
#define MOZ_HAS_MOZGLUE
#define Z_SOLO

#define JS_64BIT 1
#define JS_CODEGEN_X64 1
#define JS_DEFAULT_JITREPORT_GRANULARITY 3
#define JS_GC_ZEAL 1
#define JS_HAS_INTL_API 1
#define JS_JITSPEW 1
#define JS_PUNBOX64 1
#define JS_STANDALONE 1
#define JS_STRUCTURED_SPEW 1
#define JS_WITHOUT_NSPR 1

#define CROSS_COMPILE
#define X_DISPLAY_MISSING 1
#define EDITLINE 0
#define ENABLE_NEW_REGEXP 1
#define ENABLE_SHARED_MEMORY 1
#define ENABLE_TESTS 0
#define NO_NSPR_10_SUPPORT 1
#define STDC_HEADERS 1
#define U_STATIC_IMPLEMENTATION 1
#define U_USING_ICU_NAMESPACE 0
#define VA_COPY va_copy
#define _REENTRANT 1
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS
#define __STDC_FORMAT_MACROS

#ifndef NDEBUG
    #define DEBUG 1
    #define JS_DEBUG 1
    #define MOZ_DEBUG 1
    #define MOZ_DEBUG_RUST 1
#endif

#if defined(_WIN32)
    #define XP_WIN 1
    #define _WINDOWS 1
    #define WIN32 1
    #define WIN32_LEAN_AND_MEAN 1
    #define NOMINMAX 1

    #ifdef UNICODE
        #undef UNICODE
    #endif
    #ifdef _UNICODE
        #undef _UNICODE
    #endif

    #define GTEST_HAS_RTTI 0
    #define HAVE_64BIT_BUILD 1
    #define HAVE_ALIGNED_MALLOC 1
    #define HAVE_CPUID_H 1
    #define HAVE_FORCEINLINE 1
    #define HAVE_INTTYPES_H 1
    #define HAVE_LOCALECONV 1
    #define HAVE_MALLOC_H 1
    #define HAVE_STDINT_H 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE__GETC_NOLOCK 1
    #define HAVE__MSIZE 1
    #define MALLOC_H <malloc.h>
    #define MALLOC_USABLE_SIZE_CONST_PTR const
    #define MOZ_MEMORY 1
    #define _AMD64_ 1
    #define _CRT_NONSTDC_NO_WARNINGS 1
    #define _CRT_SECURE_NO_WARNINGS 1
    #define _USE_MATH_DEFINES 1
    #define _WIN32_IE 0x0800
    #define MOZ_DLL_PREFIX ""
    #define MOZ_DLL_SUFFIX ".dll"
#elif defined(__linux__)
    #define XP_UNIX 1
    #define XP_LINUX 1

    #define GTEST_HAS_RTTI 0
    #define HAVE_64BIT_BUILD 1
    #define HAVE_ALLOCA_H 1
    #define HAVE_BYTESWAP_H 1
    #define HAVE_CLOCK_MONOTONIC 1
    #define HAVE_CPUID_H 1
    #define HAVE_DIRENT_H 1
    #define HAVE_DLOPEN 1
    #define HAVE_FTS_H 1
    #define HAVE_GETC_UNLOCKED 1
    #define HAVE_GETOPT_H 1
    #define HAVE_GMTIME_R 1
    #define HAVE_INTTYPES_H 1
    #define HAVE_LANGINFO_CODESET 1
    #define HAVE_LIBM 1
    #define HAVE_LINUX_IF_ADDR_H 1
    #define HAVE_LINUX_PERF_EVENT_H 1
    #define HAVE_LINUX_QUOTA_H 1
    #define HAVE_LINUX_RTNETLINK_H 1
    #define HAVE_LOCALECONV 1
    #define HAVE_LOCALTIME_R 1
    #define HAVE_MALLOC_H 1
    #define HAVE_MALLOC_USABLE_SIZE 1
    #define HAVE_MEMALIGN 1
    #define HAVE_NETINET_IN_H 1
    #define HAVE_NL_TYPES_H 1
    #define HAVE_POSIX_FADVISE 1
    #define HAVE_POSIX_FALLOCATE 1
    #define HAVE_POSIX_MEMALIGN 1
    #define HAVE_PTHREAD_GETNAME_NP 1
    #define HAVE_RES_NINIT 1
    #define HAVE_SSIZE_T 1
    #define HAVE_STDINT_H 1
    #define HAVE_STRNDUP 1
    #define HAVE_SYS_MOUNT_H 1
    #define HAVE_SYS_QUEUE_H 1
    #define HAVE_SYS_QUOTA_H 1
    #define HAVE_SYS_STATFS_H 1
    #define HAVE_SYS_STATVFS_H 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_SYS_VFS_H 1
    #define HAVE_THREAD_TLS_KEYWORD 1
    #define HAVE_TM_ZONE_TM_GMTOFF 1
    #define HAVE_UNISTD_H 1
    #define HAVE_VALLOC 1
    #define HAVE_VA_COPY 1
    #define HAVE_VA_LIST_AS_ARRAY 1
    #define HAVE_VISIBILITY_ATTRIBUTE 1
    #define HAVE_VISIBILITY_HIDDEN_ATTRIBUTE 1
    #define HAVE___CXA_DEMANGLE 1
    #define MALLOC_H <malloc.h>
    #define MALLOC_USABLE_SIZE_CONST_PTR
    #define MOZ_DLL_PREFIX "lib"
    #define MOZ_DLL_SUFFIX ".so"
#else
    #error Unsupported platform
#endif
