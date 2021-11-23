#define MOZ_UNIFIED_BUILD
#include "src/intl/components/src/PluralRules.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/PluralRules.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/PluralRules.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif