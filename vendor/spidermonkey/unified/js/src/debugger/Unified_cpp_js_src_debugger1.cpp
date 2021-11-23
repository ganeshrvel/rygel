#define MOZ_UNIFIED_BUILD
#include "src/js/src/debugger/Object.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/Object.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/Object.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/Script.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/Script.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/Script.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/debugger/Source.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/debugger/Source.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/debugger/Source.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif