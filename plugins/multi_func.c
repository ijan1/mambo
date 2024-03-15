#include "multi_func.h"

#include "elf/elf_loader.h"

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
#include <llvm-c-15/llvm-c/Support.h>
#include <llvm-c-15/llvm-c/Transforms/PassBuilder.h>
#include <llvm-c-15/llvm-c/Transforms/PassManagerBuilder.h>

#define COUNT_OF(x)                                                            \
  ((sizeof(x) / sizeof(0 [x])) / ((size_t)(!(sizeof(x) % sizeof(0 [x])))))

// LLVM specific variables
static LLVMModuleRef module;
static LLVMContextRef context;
static LLVMBuilderRef builder_ref;
static LLVMTargetMachineRef tm_ref;
static LLVMExecutionEngineRef EE_ref;

// An enum to string
static const char *const LLVMTypeString[20] = {
    "void",    "fp16",   "fp32",          "fp64", "fp80",
    "fp128",   "fp64_2", "label",         "int",  "func",
    "struct",  "array",  "ptr",           "simd", "metadata",
    "x86_mmx", "token",  "simd_scalable", "bf16", "x86_mmx"};

static const char *const LLVMLinkageString[17] = {
    "LLVMExternalLinkage",
    "LLVMAvailableExternallyLinkage",
    "LLVMLinkOnceAnyLinkage",
    "LLVMLinkOnceODRLinkage",
    "LLVMLinkOnceODRAutoHideLinkage",
    "LLVMWeakAnyLinkage",
    "LLVMWeakODRLinkage",
    "LLVMAppendingLinkage",
    "LLVMInternalLinkage",
    "LLVMPrivateLinkage",
    "LLVMDLLImportLinkage",
    "LLVMDLLExportLinkage",
    "LLVMExternalWeakLinkage",
    "LLVMGhostLinkage",
    "LLVMCommonLinkage",
    "LLVMLinkerPrivateLinkage",
    "LLVMLinkerPrivateWeakLinkage"};

// MAMBO specific variables
char *error = NULL;

// Returns whether a function calls itself
static bool function_is_recursive(LLVMValueRef func);
// Returns whether a function calls 'stdlib' functions
static bool function_calls_stdlib(LLVMValueRef func);
// Given a parameter and an index, it performs """functions"""
static void handle_parameter(mambo_context *ctx, LLVMTypeKind param, size_t param_idx);
// Loads the embedded '.llvmbc' section into a MemoryBuffer, otherwise returns
// NULL if it isn't found
static LLVMMemoryBufferRef read_llvm_bitcode_segment();

int create_llvm_context() {
  LLVMInitializeNativeTarget();
  LLVMInitializeNativeAsmParser();
  LLVMInitializeNativeAsmPrinter();

  char *def_triple = LLVMGetDefaultTargetTriple();
  LLVMTargetRef target_ref = NULL;

  if (LLVMGetTargetFromTriple(def_triple, &target_ref, &error)) {
    MAMBO_ERR("Failed to get Triple.\n[ERROR] %s\n", error);
    return 1;
  }

  if (!LLVMTargetHasJIT(target_ref)) {
    MAMBO_ERR("JIT is not supported on this platform.\n");
    return 1;
  }

  tm_ref = LLVMCreateTargetMachine(target_ref, def_triple, "", "",
                                   LLVMCodeGenLevelDefault, LLVMRelocDefault,
                                   LLVMCodeModelDefault);
  assert(tm_ref);
  LLVMDisposeMessage(def_triple);

  context = LLVMContextCreate();
  builder_ref = LLVMCreateBuilderInContext(context);

  LLVMMemoryBufferRef mem_buf = read_llvm_bitcode_segment();
  if (mem_buf == NULL) {
    MAMBO_ERR("Failed to read bitcode.\n");
    return 1;
  }

  if (LLVMParseIRInContext(context, mem_buf, &module, &error)) {
    MAMBO_ERR("Failed to parse IR from file.\n[ERROR] %s\n",
             error);
    return 1;
  }

  if (LLVMCreateExecutionEngineForModule(&EE_ref, module, &error)) {
    MAMBO_ERR("Failed to create execution Engine.\n[ERROR] %s\n", error);
    return 1;
  }

  LLVMMemoryBufferRef musl_lib;
  LLVMCreateMemoryBufferWithContentsOfFile("/home/pijan/git/musl/lib/libc.a", &musl_lib, &error);
  if(error) {
    MAMBO_ERR("%s\n", error);
  }

  // We have to use SearchForAddressOfSymbol to resolve library
  // calls, because the EE isn't aware of any new libraries added in
  // using the following method to add in the 'new' symbols
  // LLVMLoadLibraryPermanently("/home/pijan/git/musl/lib/libc.so");
  // void *test = LLVMSearchForAddressOfSymbol("printf");

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

  // size_t param_count = LLVMCountParams(llvm_func);
  // for(size_t i = 0; i < param_count; i++) {
  //   LLVMValueRef parameter = LLVMGetParam(llvm_func, i);
  //   const char *param_name = LLVMTypeString[LLVMGetTypeKind(LLVMTypeOf(parameter))];
  //   MAMBO_LOG("Parameter %zu Type: %s\n", i, param_name);

  //   // Skip recursive functions
  //   if (is_recursive(llvm_func))
  //     continue;
  //   handle_parameter(ctx, LLVMGetTypeKind(LLVMTypeOf(parameter)), i);
  // }

  if(strcmp(mambo_func_name, "printf") == 0) {
    MAMBO_LOG("Printf found.\n");

    void *llvm_addr = (void *)LLVMGetFunctionAddress(EE_ref, "printf");

    if (llvm_addr == NULL) {
      MAMBO_ERR("LLVM Address is null for printf.\n");
      return 1;
    }

    assert(mambo_set_source_addr(ctx, llvm_addr) == 0);
  }

  LLVMBasicBlockRef basicBlock = LLVMGetFirstBasicBlock(llvm_func);
  while(basicBlock != NULL) {

    LLVMValueRef instruction = LLVMGetFirstInstruction(basicBlock);
    while (instruction != NULL) {

      if (LLVMGetInstructionOpcode(instruction) == LLVMGetElementPtr) {
        // Check to see if it's an array access
        if (LLVMGetNumOperands(instruction) < 3)
          continue;

        LLVMValueRef index = LLVMGetOperand(instruction, 2);
        LLVMTypeRef Type = LLVMGetGEPSourceElementType(instruction);
        uint64_t array_size = LLVMGetArrayLength(Type);

        // TODO: insert additional logic for handling other GEP cases
        // TODO: insert logic for 'statically' checking if access is
        // out of bounds in cases it can be determined and also
        // add bound checks in cases it's not possible to statically
        // determine that
        MAMBO_LOG("array size: %lu\n", array_size);;
        MAMBO_LOG("index: %lu\n", LLVMConstIntGetSExtValue(index));
      }

      instruction = LLVMGetNextInstruction(instruction);
    }

    basicBlock = LLVMGetNextBasicBlock(basicBlock);
  }

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

int hook_all_functions(mambo_context *ctx) {
  // Iterate over all functions
  LLVMValueRef current_func = LLVMGetFirstFunction(module);
  while (current_func != NULL) {
    char *func_name = LLVMGetValueName(current_func);
    function_is_recursive(current_func);

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

int fix_symbol_references(mambo_context *ctx) {
  // Set the correct linkage and address for global and static variables
  // so that the JIT'd code can use the original binary's addresses
  LLVMValueRef global = LLVMGetFirstGlobal(module);
  size_t size = 0;
  while (global != NULL) {
    const char *global_name = LLVMGetValueName2(global, &size);
    LLVMLinkage global_linkage = LLVMGetLinkage(global);

    if (global_linkage == LLVMExternalLinkage ||
        global_linkage == LLVMInternalLinkage) {
      MAMBO_LOG("Global name: %s\n", global_name);
      MAMBO_LOG("Linkage: %s\n\n", LLVMLinkageString[global_linkage]);

      void *global_addr =
          (void *)get_symbol_addr_by_name(global_name, STT_OBJECT);
      MAMBO_LOG("Global address: %p\n", global_addr);
      if (global_addr == NULL) {
        MAMBO_ERR("Failed to get global's address.\n");
        global = LLVMGetNextGlobal(global);
        continue;
      }

      // We have to mark the global as external and remove its initializer
      // so that we can hook it up to the real address inside our binary
      LLVMSetLinkage(global, LLVMExternalLinkage);
      LLVMSetInitializer(global, NULL);
      LLVMAddGlobalMapping(EE_ref, global, global_addr);
      MAMBO_LOG("Successfully added mapping for: '%s'\n", global_name);
    }

    global = LLVMGetNextGlobal(global);
  } // global != NULL

  // void (*addr)() = (void (*)())LLVMGetFunctionAddress(EE_ref,
  // "update_global"); addr();

  return MAMBO_SUCCESS;
}

int initialise_llvm(mambo_context *ctx) {
  assert(create_llvm_context() == MAMBO_SUCCESS);
  assert(hook_all_functions(ctx) == MAMBO_SUCCESS);
  assert(fix_symbol_references(ctx) == MAMBO_SUCCESS);

  return MAMBO_SUCCESS;
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

int cleanup(mambo_context *ctx) {
  (void) ctx;

  LLVMDisposeExecutionEngine(EE_ref); // The EE disposes of the module
  // LLVMDisposeModule(module);
  LLVMContextDispose(context);
  LLVMDisposeTargetMachine(tm_ref);
  LLVMDisposeBuilder(builder_ref);

  LLVMShutdown();

  return 0;
}

__attribute__((constructor)) void function_count_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_entry_cb(ctx, initialise_llvm);
  mambo_register_exit_cb(ctx, cleanup);

  MAMBO_LOG("Initialised Multi-Function\n\n");
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
static void handle_parameter(mambo_context *ctx, LLVMTypeKind param, size_t param_idx) {
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

static bool function_is_recursive(LLVMValueRef func) {
  const char *function_name = LLVMGetValueName(func);

  LLVMBasicBlockRef basic_block = LLVMGetFirstBasicBlock(func);
  while(basic_block != NULL) {
    // const char *bb_name = LLVMGetBasicBlockName(basic_block);

    LLVMValueRef instruction = LLVMGetFirstInstruction(basic_block);
    while (instruction != NULL) {
      LLVMOpcode type = LLVMGetInstructionOpcode(instruction);

      if(type == LLVMCall) {
        const char *called_func_name =
            LLVMGetValueName(LLVMGetCalledValue(instruction));
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

static bool function_calls_stdlib(LLVMValueRef func) {
  const char *function_name = LLVMGetValueName(func);

  LLVMBasicBlockRef basic_block = LLVMGetFirstBasicBlock(func);
  while(basic_block != NULL) {
    // const char *bb_name = LLVMGetBasicBlockName(basic_block);

    LLVMValueRef instruction = LLVMGetFirstInstruction(basic_block);
    while (instruction != NULL) {
      LLVMOpcode type = LLVMGetInstructionOpcode(instruction);

      if(type == LLVMCall) {
        const char *called_func_name =
            LLVMGetValueName(LLVMGetCalledValue(instruction));
      } // type == LLVMCall

      instruction = LLVMGetNextInstruction(instruction);
    }

    basic_block = LLVMGetNextBasicBlock(basic_block);
  }

  return false;
}

static LLVMMemoryBufferRef read_llvm_bitcode_segment() {
  if (pthread_mutex_lock(&global_data.exec_allocs.mutex) != 0) {
    MAMBO_ERR("Failed to lock interval map mutex.\n");
    exit(EXIT_FAILURE);
  }

  Elf_Data *data = NULL;
  interval_map *imap = &global_data.exec_allocs;
  for (ssize_t i = 0; i < imap->entry_count; i++) {
    const interval_map_entry *fm = &imap->entries[i];

    Elf *elf = elf_begin(fm->fd, ELF_C_READ, NULL);
    ELF_EHDR *ehdr;
    if (elf != NULL) {

      GElf_Shdr shdr;
      Elf_Scn *scn = NULL;
      ehdr = ELF_GETEHDR(elf);
      while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        const char *section_name =
            elf_strptr(elf, ehdr->e_shstrndx, shdr.sh_name);
        if (section_name && strcmp(section_name, ".llvmbc") == 0) {
          data = elf_getdata(scn, NULL);
          MAMBO_LOG("LLVM Bitcode size: %lu\n", data->d_size);
          if (pthread_mutex_unlock(&imap->mutex) != 0) {
            MAMBO_ERR("Failed to unlock interval map mutex.\n");
            exit(EXIT_FAILURE);
          }

          LLVMMemoryBufferRef mem_buf = LLVMCreateMemoryBufferWithMemoryRange(
              data->d_buf, data->d_size, ".llvmbc", true);

          return mem_buf;
        } // if (section_name == ".llvmbc")
      }   // while elf_nextscn
    }     // if (elf != NULL)
  }       // for imap->entry_count

  if (pthread_mutex_unlock(&imap->mutex) != 0) {
    MAMBO_ERR("Failed to unlock interval map mutex.\n");
    exit(EXIT_FAILURE);
  }

  return NULL;
}
