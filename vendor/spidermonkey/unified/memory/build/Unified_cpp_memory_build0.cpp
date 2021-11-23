#define IMPL_MFBT 1
#define MOZ_UNIFIED_BUILD
#include "src/memory/build/fallback.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/memory/build/fallback.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/memory/build/fallback.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif