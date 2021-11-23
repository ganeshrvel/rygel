#define MOZ_UNIFIED_BUILD
#include "src/js/src/gc/Zone.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/gc/Zone.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/gc/Zone.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif