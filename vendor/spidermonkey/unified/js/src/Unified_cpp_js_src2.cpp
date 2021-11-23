#define MOZ_UNIFIED_BUILD
#include "src/js/src/builtin/Promise.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/Promise.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/Promise.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/Reflect.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/Reflect.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/Reflect.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/ReflectParse.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/ReflectParse.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/ReflectParse.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/Stream.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/Stream.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/Stream.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/String.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/String.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/String.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/Symbol.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/Symbol.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/Symbol.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif