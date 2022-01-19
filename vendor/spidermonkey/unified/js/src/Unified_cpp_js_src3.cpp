#define MOZ_UNIFIED_BUILD
#include "src/js/src/builtin/TestingFunctions.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/TestingFunctions.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/TestingFunctions.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/TestingUtility.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/TestingUtility.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/TestingUtility.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/WeakMapObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/WeakMapObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/WeakMapObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/WeakRefObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/WeakRefObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/WeakRefObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/WeakSetObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/WeakSetObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/WeakSetObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/builtin/intl/Collator.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/builtin/intl/Collator.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/builtin/intl/Collator.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif