#define MOZ_UNIFIED_BUILD
#include "src/js/src/editline/editline.c"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/editline/editline.c uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/editline/editline.c defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/editline/sysunix.c"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/editline/sysunix.c uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/editline/sysunix.c defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif