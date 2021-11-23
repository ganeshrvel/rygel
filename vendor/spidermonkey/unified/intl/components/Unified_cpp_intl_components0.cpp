#define MOZ_UNIFIED_BUILD
#include "src/intl/components/src/Calendar.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/Calendar.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/Calendar.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/intl/components/src/DateTimeFormat.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/DateTimeFormat.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/DateTimeFormat.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/intl/components/src/DateTimePatternGenerator.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/DateTimePatternGenerator.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/DateTimePatternGenerator.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/intl/components/src/NumberFormat.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/NumberFormat.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/NumberFormat.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/intl/components/src/NumberFormatFields.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/NumberFormatFields.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/NumberFormatFields.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/intl/components/src/NumberFormatterSkeleton.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/intl/components/src/NumberFormatterSkeleton.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/intl/components/src/NumberFormatterSkeleton.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif