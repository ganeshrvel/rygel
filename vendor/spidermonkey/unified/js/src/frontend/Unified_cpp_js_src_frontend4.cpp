#define MOZ_UNIFIED_BUILD
#include "src/js/src/frontend/ObjLiteral.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/ObjLiteral.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/ObjLiteral.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/ObjectEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/ObjectEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/ObjectEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/OptionalEmitter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/OptionalEmitter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/OptionalEmitter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/ParseContext.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/ParseContext.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/ParseContext.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/ParseNode.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/ParseNode.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/ParseNode.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/frontend/ParseNodeVerify.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/frontend/ParseNodeVerify.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/frontend/ParseNodeVerify.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif