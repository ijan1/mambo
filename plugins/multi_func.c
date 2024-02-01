#include "multi_func.h"

#include "api/helpers.h"
#include "api/plugin_support.h"
#include "elf/elf_loader.h"
#include "plugins.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <llvm-c-15/llvm-c/Core.h>
#include <llvm-c-15/llvm-c/Error.h>
#include <llvm-c-15/llvm-c/ExecutionEngine.h>
#include <llvm-c-15/llvm-c/IRReader.h>
#include <llvm-c-15/llvm-c/Orc.h>
#include <llvm-c-15/llvm-c/OrcEE.h>
#include <llvm-c-15/llvm-c/Target.h>
#include <llvm-c-15/llvm-c/TargetMachine.h>
#include <llvm-c-15/llvm-c/Types.h>

#define COUNT_OF(x)                                                            \
  ((sizeof(x) / sizeof(0 [x])) / ((size_t)(!(sizeof(x) % sizeof(0 [x])))))

int foobar_global;

// LLVM specific variables
static LLVMModuleRef module;
static LLVMContextRef context;
static LLVMBuilderRef builder_ref;
static LLVMTargetMachineRef tm_ref;
static LLVMExecutionEngineRef EE_ref;

// An enum to string converter
static const char *const LLVM_type_name[20] = {
    "void",    "fp16",   "fp32",          "fp64", "fp80",
    "fp128",   "fp64_2", "label",         "int",  "func",
    "struct",  "array",  "ptr",           "simd", "metadata",
    "x86_mmx", "token",  "simd_scalable", "bf16", "x86_mmx"};

// MAMBO specific variable
static CPU_t cpu;

int initialise_llvm() {
  char *error = NULL;
  const char *file_path = "binaries/calculator.ll";

  LLVMInitializeNativeTarget();
  LLVMInitializeNativeAsmParser();
  LLVMInitializeNativeAsmPrinter();

  char *def_triple = LLVMGetDefaultTargetTriple();
  LLVMTargetRef target_ref = NULL;

  if (LLVMGetTargetFromTriple(def_triple, &target_ref, &error)) {
    LLVM_ERR("Failed to get Triple.\n[ERROR] %s\n", error);
  }

  if (!LLVMTargetHasJIT(target_ref)) {
    LLVM_ERR("JIT is not supported on this platform.\n");
  }

  tm_ref = LLVMCreateTargetMachine(target_ref, def_triple, "", "",
                                   LLVMCodeGenLevelDefault, LLVMRelocDefault,
                                   LLVMCodeModelDefault);
  assert(tm_ref);
  LLVMDisposeMessage(def_triple);

  context = LLVMContextCreate();
  builder_ref = LLVMCreateBuilderInContext(context);

  LLVMMemoryBufferRef mem_buf;
  if (LLVMCreateMemoryBufferWithContentsOfFile(file_path, &mem_buf, &error)) {
    LLVM_ERR("Failed to read file '%s'.\n[ERROR] %s\n", file_path, error);
  }

  if (LLVMParseIRInContext(context, mem_buf, &module, &error)) {
    LLVM_ERR("Failed to parse IR from file '%s'.\n[ERROR] %s\n", file_path,
             error);
  }

  if (LLVMCreateExecutionEngineForModule(&EE_ref, module, &error)) {
    LLVM_ERR("Failed to create execution Engine.\n[ERROR] %s\n", error);
  }

  return MAMBO_SUCCESS;
}

int func_pre_callback(mambo_context *ctx) {
  char *mambo_func_name = mambo_get_cb_function_name(ctx);
  void *mambo_func_addr = mambo_get_source_addr(ctx);

  MAMBO_LOG("Pre-callback for: %s\n", mambo_func_name);
  MAMBO_LOG("Function address: %p\n", mambo_func_addr);

  LLVMValueRef llvm_func = LLVMGetNamedFunction(module, mambo_func_name);
  if (llvm_func == NULL) {
    MAMBO_LOG("LLVM address is null. Skipping substitution.\n");
    return 1;
  }

  size_t param_count = LLVMCountParams(llvm_func);
  for(size_t i = 0; i < param_count; i++) {
    LLVMValueRef parameter = LLVMGetParam(llvm_func, i);
    const char *param_name = LLVM_type_name[LLVMGetTypeKind(LLVMTypeOf(parameter))];
    MAMBO_LOG("Parameter %zu Type: %s\n", i, param_name);

    // Skip recursive functions
    if (is_recursive(llvm_func))
      continue;
    handle_parameter(ctx, LLVMGetTypeKind(LLVMTypeOf(parameter)), i);
  }

  // if(strcmp(mambo_func_name, "printf")) {
  //   printf("[MAMBO] Printf found.\n");

  //   void *llvm_addr = (void *)LLVMGetFunctionAddress(EE_ref, "printf");
  //   if (llvm_addr == NULL) {
  //     printf("[MAMBO] LLVM Address is null for printf.\n");
  //     return 1;
  //   }

  //   assert(mambo_set_source_addr(ctx, llvm_addr) == 0);
  // }

  // void *llvm_addr = (void *)LLVMGetFunctionAddress(EE_ref, mambo_func_name);
  // if (llvm_addr == NULL) {
  //   MAMBO_LOG("LLVM address is null. Skipping substitution.\n");
  //   return 1;
  // }

  // if (rand() % 2) {
  //   MAMBO_LOG("Coinflip successful. Substituting with LLVM function.\n");
  //   MAMBO_LOG("New address: %p\n", llvm_func);
  //   assert(mambo_set_source_addr(ctx, llvm_func) == 0);
  // }

  return MAMBO_SUCCESS;
}

int func_post_callback(mambo_context *ctx) {
  char *mambo_func_name = mambo_get_cb_function_name(ctx);
  void *mambo_func_addr = mambo_get_source_addr(ctx);

  MAMBO_LOG("Post-callback for: %s\n", mambo_func_name);
  MAMBO_LOG("Function address: %p\n\n", mambo_func_addr);

  return 0;
}

// NOTE: unused for now
// int pre_hook(mambo_context *ctx) {
//   emit_push(ctx, (1 << reg0));
//   emit_set_reg_ptr(ctx, reg0, ctx);
//   emit_safe_fcall(ctx, func_pre_callback, 1);
//   emit_pop(ctx, (1 << reg0));
//   return 0;
// }
//
// int post_hook(mambo_context *ctx) {
//   emit_push(ctx, (1 << reg0));
//   emit_set_reg_ptr(ctx, reg0, ctx);
//   emit_safe_fcall(ctx, func_post_callback, 1);
//   emit_pop(ctx, (1 << reg0));
//   return 0;
// }

int hook_all_functions(mambo_context *ctx) {
  // Iterate over all functions
  LLVMValueRef current_func = LLVMGetFirstFunction(module);
  while (current_func != NULL) {
    const char *func_name = LLVMGetValueName(current_func);
    is_recursive(current_func);

    // Create hooks for the function
    int result = mambo_register_function_cb(ctx, func_name, func_pre_callback,
                                            func_post_callback, 1);
    assert(result == MAMBO_SUCCESS);
    MAMBO_LOG("Added hook for: %s\n", func_name);

    // Move to the next function
    current_func = LLVMGetNextFunction(current_func);
  }

  return MAMBO_SUCCESS;
}

void test() {
  LLVMValueRef global = LLVMGetFirstGlobal(module);
  while (global != NULL) {

    global = LLVMGetNextGlobal(global);
  } // global != NULL
}

int pre_thread_callback(mambo_context *ctx) {

  LLVMValueRef global = LLVMGetNamedGlobal(module, "foobar_global");
  if (global == NULL) {
    MAMBO_LOG("Failed to find global variable inside LLVM Module.\n");
    return 1;
  }

  void *global_addr =
      (void *)get_symbol_addr_by_name("foobar_global", STT_OBJECT);
  if (global_addr == NULL) {
    MAMBO_LOG("Failed to find address of global variable in ELF.\n");
    return 1;
  }

  LLVMAddGlobalMapping(EE_ref, global, global_addr);

  // *(int *)global_addr = 10;
  // void *addr = (void *)LLVMGetGlobalValueAddress(EE_ref, "foobar_global");
  // printf("Global var address: %p\n", addr);

  void (*addr)() = (void (*)())LLVMGetFunctionAddress(EE_ref, "update_global");
  addr();

  return MAMBO_SUCCESS;
}

__attribute__((constructor)) void function_count_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  assert(initialise_llvm() == 0);
  assert(hook_all_functions(ctx) == 0);

  // Set the CPU
  initialise_cpu(&cpu);

  // Seed PRNG
  srand(time(NULL));

  // Register callbacks
  mambo_register_pre_thread_cb(ctx, &pre_thread_callback);
  MAMBO_LOG("Initialised Multi-Function\n\n");
}

__attribute__((destructor)) void cleanup() {
  LLVMDisposeExecutionEngine(EE_ref); // The EE disposes of the module
  // LLVMDisposeModule(module);
  LLVMContextDispose(context);
  LLVMDisposeTargetMachine(tm_ref);
  LLVMDisposeBuilder(builder_ref);

  LLVMShutdown();
}

// NOTE: only the first 8 parameters are passed through registers.
// The others are passed through the stack.
static enum reg index_to_reg_no(size_t param_idx) {
  if(param_idx > 31) {
    MAMBO_LOG("Invalid parameter index\n");
    return reg_invalid;
  }

  return (enum reg) param_idx;
}

// NOTE: care should be taken with recursive functions
void handle_parameter(mambo_context *ctx, LLVMTypeKind param, size_t param_idx) {
  enum reg arm_register = index_to_reg_no(param_idx);
  switch(param) {
    case LLVMVoidTypeKind:
    case LLVMHalfTypeKind:
    case LLVMFloatTypeKind:
    case LLVMDoubleTypeKind:
    case LLVMX86_FP80TypeKind:
    case LLVMFP128TypeKind:
    case LLVMPPC_FP128TypeKind:
    case LLVMLabelTypeKind:
      break;
    case LLVMIntegerTypeKind:
      emit_set_reg(ctx, arm_register, 10);
      break;
    case LLVMFunctionTypeKind:
    case LLVMStructTypeKind:
    case LLVMArrayTypeKind:
    case LLVMPointerTypeKind:
    case LLVMVectorTypeKind:
    case LLVMMetadataTypeKind:
    case LLVMX86_MMXTypeKind:
    case LLVMTokenTypeKind:
    case LLVMScalableVectorTypeKind:
    case LLVMBFloatTypeKind:
    case LLVMX86_AMXTypeKind:
    default:
      break;
  }
}

bool is_recursive(LLVMValueRef func) {
  const char *function_name = LLVMGetValueName(func);
  MAMBO_LOG("Function name: %s\n", function_name);

  LLVMBasicBlockRef basic_block = LLVMGetFirstBasicBlock(func);
  while(basic_block != NULL) {
    const char *bb_name = LLVMGetBasicBlockName(basic_block);
    MAMBO_LOG("Basic block: %s\n", bb_name);

    LLVMValueRef instruction = LLVMGetFirstInstruction(basic_block);
    while (instruction != NULL) {
      LLVMOpcode type = LLVMGetInstructionOpcode(instruction);

#if defined(MJAO)
      LLVMDumpValue(instruction);
      printf("\n");
#endif

      if(type == LLVMCall) {
        const char *called_func_name =
            LLVMGetValueName(LLVMGetCalledValue(instruction));
        MAMBO_LOG("Called function name: %s\n", called_func_name);
        if(called_func_name == function_name) {
          return true;
        } // called_name == func_name
      } // type == LLVMCall

      instruction = LLVMGetNextInstruction(instruction);
    }

    basic_block = LLVMGetNextBasicBlock(basic_block);
  }

  return false;
}
