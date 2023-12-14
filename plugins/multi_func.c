#include "multi_func.h"

#include "dbm.h"
#include "api/plugin_support.h"

#include <llvm-c-15/llvm-c/TargetMachine.h>
#include <llvm-c-15/llvm-c/Core.h>
#include <llvm-c-15/llvm-c/Error.h>
#include <llvm-c-15/llvm-c/ExecutionEngine.h>
#include <llvm-c-15/llvm-c/Orc.h>
#include <llvm-c-15/llvm-c/OrcEE.h>
#include <llvm-c-15/llvm-c/Target.h>
#include <llvm-c-15/llvm-c/Types.h>

#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// TODO: make an err function taking in string and var args
// and then just exiting since it seems to be a recurring theme

extern void function_watch_try_addp(watched_functions_t *self, char *name,
                                    void *addr);

static func_vtable_t global_vtable;

// TODO: don't use global data, the context has vm info
// ctx.vm.op = op;
// ctx.vm.addr = (void *)addr;
// ctx.vm.size = size;
// ctx.vm.prot = prot;
// ctx.vm.flags = flags;
// ctx.vm.filedes = fd;
// ctx.vm.off = off;

func_t init_func(char *name) {
  uintptr_t addr = interval_map_search_by_name(&global_data.exec_allocs, name);

  func_t ret = {.name = name, .loc = addr};
  return ret;
}

int func_swap_cb(mambo_context *ctx) {
  fprintf(stderr, "[MAMBO] Swapping (%s, 0x%lx) with (%s, 0x%lx)\n",
          global_vtable.original.name, global_vtable.original.loc,
          global_vtable.to_swap.name, global_vtable.to_swap.loc);

  void *new_addr = (void *)global_vtable.to_swap.loc;
  mambo_set_source_addr(ctx, new_addr);
  return 0;
}

void add_function_callback(mambo_context *ctx, watched_functions_t *self,
                           char *name, void *addr) {
  mambo_register_function_cb(ctx, name, &func_swap_cb, NULL, 2);
  function_watch_try_addp(self, name, addr);
}

uintptr_t interval_map_search_by_name(interval_map *imap,
                                      const char *symbol_name) {
  if (pthread_mutex_lock(&imap->mutex) != 0) {
    fprintf(stderr, "Failed to lock interval map mutex.\n");
    exit(EXIT_FAILURE);
  }

  for (ssize_t i = 0; i < imap->entry_count; i++) {
    const interval_map_entry *fm = &imap->entries[i];

    Elf *elf = elf_begin(fm->fd, ELF_C_READ, NULL);
    ELF_EHDR *ehdr;
    if (elf != NULL) {

      ehdr = ELF_GETEHDR(elf);
      // if (ehdr->e_type == ET_DYN) {
      //   printf("[MAMBO] What happens here?: 0x%lx\n", fm.start);
      //   // I see, I have to add the fm.start to the sym.st_value to
      //   // get the correct address
      // }

      Elf_Scn *scn = NULL;
      GElf_Shdr shdr;
      while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
          Elf_Data *edata = elf_getdata(scn, NULL);
          assert(edata != NULL);

          int sym_count =
              shdr.sh_size / shdr.sh_entsize; // narrowing conversion
          GElf_Sym sym;

          for (int i = 0; i < sym_count; i++) {
            gelf_getsym(edata, i, &sym);
            if (sym.st_value != 0 && ELF32_ST_TYPE(sym.st_info) == STT_FUNC) {
              const char *s_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
              if (strcmp(symbol_name, s_name) == 0) {
                pthread_mutex_unlock(&imap->mutex);
                return fm->start + sym.st_value;
              }
            }
          }
        }
      } // while elf_nextscn
    }   // if (elf != NULL)
  }     // for imap->entry_count

  if (pthread_mutex_unlock(&imap->mutex) != 0) {
    fprintf(stderr, "Failed to unlock interval map mutex.\n");
    exit(EXIT_FAILURE);
  }

  return (uintptr_t)NULL;
}

int pre_thread_handler_swap(mambo_context *ctx) {
  (void)ctx;

  func_t original = init_func("foo");
  func_t to_replace_with = init_func("meow");

  global_vtable.original = original;
  global_vtable.to_swap = to_replace_with;

  add_function_callback(ctx, &global_data.watched_functions, original.name,
                        (void *)original.loc);

  return 0;
}

int pre_thread_handler_elf_swap(mambo_context *ctx) {
  Elf *elf;
  struct elf_loader_auxv auxv;
  uintptr_t entry_addr = 0;
  fprintf(stderr, "[MAMBO] Loading alternative elf file!\n");
  load_elf("/tmp/alt.out", &elf, &auxv, &entry_addr, false);
  fprintf(stderr, "[MAMBO] At base: 0x%lx\n", auxv.at_base);

  // int res = interval_map_search_by_name(&global_data.exec_allocs, "meow");

  func_t original = init_func("foo");
  func_t to_replace_with = init_func("mjao");

  global_vtable.original = original;
  global_vtable.to_swap = to_replace_with;

  add_function_callback(ctx, &global_data.watched_functions, original.name,
                        (void *)original.loc);
}

void initialise_llvm() {
  LLVMInitializeAArch64Target();
  LLVMInitializeAArch64AsmParser();
  LLVMInitializeAArch64AsmPrinter();

  char *def_triple = LLVMGetDefaultTargetTriple();
  char *error = NULL;
  LLVMTargetRef target_ref = NULL;

  if (LLVMGetTargetFromTriple(def_triple, &target_ref, &error)) {
    fprintf(stderr, "[ERROR] Failed to get triple.\n [ERROR] %s\n", error);
  }

  if(!LLVMTargetHasJIT(target_ref)) {
    fprintf(stderr, "[ERROR] JIT is not supported on this platform.\n");
  }
}

// We are reading in the data after mambo has been initialised and before the
// threads are ready to run in case there's some kind of information-leak
// possiblity before mambo's internals have been set-up

// This is very platform-dependent. The glibc dynamic loader passes the
// argc, argv, and envp to ELF constructors, so you can access the program
// arguments in this way. To my knowledge, this is an undocumented dynamic
// loader feature, so you probably should not rely on this behavior.
// From:
// https://stackoverflow.com/questions/58999228/picking-up-value-of-attribute-constructor-function-in-main
// We can't use 'global_data' here because this all happens before 'main'
__attribute__((constructor)) void function_count_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  // mambo_register_pre_thread_cb(ctx, &pre_thread_handler_swap);
  mambo_register_pre_thread_cb(ctx, &pre_thread_handler_elf_swap);
  fprintf(stderr, "[MAMBO] Initialised Multi Function\n\n");

  initialise_llvm();
}
