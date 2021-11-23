#define MOZ_UNIFIED_BUILD
#include "src/js/src/wasm/WasmCompile.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmCompile.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmCompile.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmContext.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmContext.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmContext.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmDebug.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmDebug.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmDebug.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmFrame.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmFrame.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmFrame.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmFrameIter.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmFrameIter.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmFrameIter.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "src/js/src/wasm/WasmGC.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "src/js/src/wasm/WasmGC.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "src/js/src/wasm/WasmGC.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif