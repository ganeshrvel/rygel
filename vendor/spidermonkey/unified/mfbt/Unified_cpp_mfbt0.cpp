#define IMPL_MFBT 1
#undef MOZ_HAS_MOZGLUE
#define MOZ_UNIFIED_BUILD
#include "src/mfbt/Assertions.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/Assertions.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/Assertions.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/ChaosMode.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/ChaosMode.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/ChaosMode.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/Compression.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/Compression.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/Compression.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/FloatingPoint.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/FloatingPoint.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/FloatingPoint.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/HashFunctions.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/HashFunctions.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/HashFunctions.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/JSONWriter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/JSONWriter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/JSONWriter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/Poison.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/Poison.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/Poison.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/RandomNum.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/RandomNum.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/RandomNum.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/SHA1.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/SHA1.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/SHA1.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/TaggedAnonymousMemory.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/TaggedAnonymousMemory.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/TaggedAnonymousMemory.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/UniquePtrExtensions.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/UniquePtrExtensions.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/UniquePtrExtensions.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/Unused.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/Unused.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/Unused.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/Utf8.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/Utf8.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/Utf8.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/double-conversion/double-conversion/bignum-dtoa.cc"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/double-conversion/double-conversion/bignum-dtoa.cc uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/double-conversion/double-conversion/bignum-dtoa.cc defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/double-conversion/double-conversion/bignum.cc"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/double-conversion/double-conversion/bignum.cc uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/double-conversion/double-conversion/bignum.cc defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/mfbt/double-conversion/double-conversion/cached-powers.cc"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/mfbt/double-conversion/double-conversion/cached-powers.cc uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/mfbt/double-conversion/double-conversion/cached-powers.cc defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif