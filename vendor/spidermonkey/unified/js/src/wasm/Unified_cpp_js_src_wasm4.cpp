#define MOZ_UNIFIED_BUILD
#include "src/js/src/wasm/WasmTlsData.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmTlsData.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmTlsData.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmTypeDef.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmTypeDef.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmTypeDef.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmTypes.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmTypes.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmTypes.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmValType.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmValType.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmValType.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmValidate.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmValidate.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmValidate.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmValue.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmValue.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmValue.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif