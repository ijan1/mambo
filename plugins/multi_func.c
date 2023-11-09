#include "multi_func.h"
#include "../dbm.h"
#include "api/plugin_support.h"
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <assert.h>

// TODO: make an err function taking in string and var args
// and then just exiting since it seems to be a recurring theme

extern void function_watch_try_addp(watched_functions_t *self, char *name,
                                    void *addr);

static func_vtable_t global_vtable;

func_t init_func(char *name) {
  uintptr_t addr = interval_map_search_by_name(&global_data.exec_allocs, name);

  func_t ret  = {.name = name, .loc = addr };
  return ret;
}

int func_swap_cb(mambo_context *ctx) {
  fprintf(stderr, "Swapping (%s, 0x%lx) with (%s, 0x%lx)\n",
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

uintptr_t interval_map_search_by_name(interval_map *imap, const char *symbol_name) {
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

          int sym_count = shdr.sh_size / shdr.sh_entsize; // narrowing conversion
          GElf_Sym sym;

          for (int i = 0; i < sym_count; i++) {
            gelf_getsym(edata, i, &sym);
            if (sym.st_value != 0 && ELF32_ST_TYPE(sym.st_info) == STT_FUNC) {
              const char *s_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
              if(strcmp(symbol_name, s_name) == 0) {
                pthread_mutex_unlock(&imap->mutex);
                return fm->start + sym.st_value;
              }
            }
          }
        }
      } // while elf_nextscn
    }   // if (elf != NULL)
  }     // for imap->entry_count
  // That is way too many levels of nesting unfortunately I don't think much
  // can be done about it

  if (pthread_mutex_unlock(&imap->mutex) != 0) {
    fprintf(stderr, "Failed to unlock interval map mutex.\n");
    exit(EXIT_FAILURE);
  }

  return (uintptr_t)NULL;
}

int pre_thread_handler(mambo_context *ctx) {
  (void)ctx;

  func_t original = init_func("err");
  func_t to_replace_with = init_func("launch_nukes");

  global_vtable.original = original;
  global_vtable.to_swap = to_replace_with;

  add_function_callback(ctx, &global_data.watched_functions, original.name,
                        (void *)original.loc);

  return 0;
}

/*
  Used to read in the 'secondary' and 'ternary' ELF files from which the
  virtual functions will be build.
*/
int read_elf(const char *filepath, mambo_context *ctx) {
  ELF_SHDR *shdr;
  ELF_EHDR *ehdr;
  Elf_Kind kind;
  size_t shnum;

  int fd = open(filepath, O_RDONLY);
  if (fd < 0) {
    printf("Couldn't open file %s\n", filepath);
    exit(EXIT_FAILURE);
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    printf("Error setting ELF version\n");
    exit(EXIT_FAILURE);
  }

  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if (elf == NULL) {
    printf("Error opening ELF file: %s: %s\n", filepath, elf_errmsg(-1));
    exit(EXIT_FAILURE);
  }

  kind = elf_kind(elf);
  if (kind != ELF_K_ELF) {
    printf("File %s isn't an ELF file\n", filepath);
    exit(EXIT_FAILURE);
  }

  ehdr = ELF_GETEHDR(elf);
  if (ehdr == NULL) {
    printf("Error reading the ELF executable header: %s\n", elf_errmsg(-1));
    exit(EXIT_FAILURE);
  }

  // XXX: 32-bit?
  if (ehdr->e_ident[EI_CLASS] != ELF_CLASS) {
    printf("Not a 32-bit ELF file\n");
    exit(EXIT_FAILURE);
  }

  if (ehdr->e_machine != EM_MACHINE) {
    printf("Not compiled for ARM\n");
    exit(EXIT_FAILURE);
  }

  Elf_Scn *scn = NULL;
  Elf_Data *symtab_data = NULL;
  GElf_Sym sym;

  elf_getshdrnum(elf, &shnum);
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    shdr = ELF_GETSHDR(scn);

    if (shdr->sh_type == SHT_SYMTAB) {
      symtab_data = elf_getdata(scn, NULL);
      assert(symtab_data != NULL);

      size_t sym_count = shdr->sh_size / shdr->sh_entsize;
      for (int i = 0; i < sym_count;
           i++) { // comparison of signed with unsigned
        gelf_getsym(symtab_data, i, &sym);
        // NOTE: look into why 'ELF_ST_TYPE' doesn't work
        if (sym.st_name == 0 || ELF32_ST_TYPE(sym.st_info) != STT_FUNC)
          continue;

        char *fname = elf_strptr(elf, shdr->sh_link, sym.st_name);
        assert(fname != NULL);
        fprintf(stderr, "[MAMBO] Found function symbol: %s\n", fname);
      } // for sym_count
    }   // if sh_type == SHT_SYMTAB
  }     // while nextscn
  return 0;

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

  mambo_register_pre_thread_cb(ctx, &pre_thread_handler);
  fprintf(stderr, "[MAMBO] Initialised Multi Function\n\n");
}
