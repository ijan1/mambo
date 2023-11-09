/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2021 The University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   TODO
*/
#ifdef PLUGINS_NEW

#include "../elf/elf_loader.h"
#include "../plugins.h"
#include <fcntl.h>
#include <gelf.h>
#include <stdint.h>

typedef struct {
  char *name;
  uintptr_t loc;
} func_t;

#define FUNC_NUM 3

typedef struct {
  func_t original;
  func_t to_swap; // Idea have some sort of additional/alternative params to
                  // pass in
  func_t swap[FUNC_NUM];
} func_vtable_t;

func_t init_func(char *name);
int func_swap_cb(mambo_context *ctx);
int pre_thread_handler_swap(mambo_context *ctx);
int pre_thread_handler_elf_swap(mambo_context *ctx);
int read_elf(const char *filepath, mambo_context *ctx);
void add_function_callback(mambo_context *ctx, watched_functions_t *self,
                           char *name, void *addr);
uintptr_t interval_map_search_by_name(interval_map *imap,
                                      const char *symbol_name);
/*
  Used to read in the 'secondary' and 'ternary' ELF files from which the
  virtual functions will be build.
*/
// int read_elf(const char *filepath, mambo_context *ctx) {
//   (void)ctx;
//   ELF_SHDR *shdr;
//   ELF_EHDR *ehdr;
//   Elf_Kind kind;
//   size_t shnum;
//
//   int fd = open(filepath, O_RDONLY);
//   if (fd < 0) {
//     printf("Couldn't open file %s\n", filepath);
//     exit(EXIT_FAILURE);
//   }
//
//   if (elf_version(EV_CURRENT) == EV_NONE) {
//     printf("Error setting ELF version\n");
//     exit(EXIT_FAILURE);
//   }
//
//   Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
//   if (elf == NULL) {
//     printf("Error opening ELF file: %s: %s\n", filepath, elf_errmsg(-1));
//     exit(EXIT_FAILURE);
//   }
//
//   kind = elf_kind(elf);
//   if (kind != ELF_K_ELF) {
//     printf("File %s isn't an ELF file\n", filepath);
//     exit(EXIT_FAILURE);
//   }
//
//   ehdr = ELF_GETEHDR(elf);
//   if (ehdr == NULL) {
//     printf("Error reading the ELF executable header: %s\n", elf_errmsg(-1));
//     exit(EXIT_FAILURE);
//   }
//
//   // XXX: 32-bit?
//   if (ehdr->e_ident[EI_CLASS] != ELF_CLASS) {
//     printf("Not a 32-bit ELF file\n");
//     exit(EXIT_FAILURE);
//   }
//
//   if (ehdr->e_machine != EM_MACHINE) {
//     printf("Not compiled for ARM\n");
//     exit(EXIT_FAILURE);
//   }
//
//   Elf_Scn *scn = NULL;
//   Elf_Data *symtab_data = NULL;
//   GElf_Sym sym;
//
//   elf_getshdrnum(elf, &shnum);
//   while ((scn = elf_nextscn(elf, scn)) != NULL) {
//     shdr = ELF_GETSHDR(scn);
//
//     if (shdr->sh_type == SHT_SYMTAB) {
//       symtab_data = elf_getdata(scn, NULL);
//       assert(symtab_data != NULL);
//
//       size_t sym_count = shdr->sh_size / shdr->sh_entsize;
//       for (int i = 0; i < sym_count;
//            i++) { // comparison of signed with unsigned
//         gelf_getsym(symtab_data, i, &sym);
//         // NOTE: look into why 'ELF_ST_TYPE' doesn't work
//         if (sym.st_name == 0 || ELF32_ST_TYPE(sym.st_info) != STT_FUNC)
//           continue;
//
//         char *fname = elf_strptr(elf, shdr->sh_link, sym.st_name);
//         assert(fname != NULL);
//         fprintf(stderr, "[MAMBO] Found function symbol: %s\n", fname);
//       } // for sym_count
//     }   // if sh_type == SHT_SYMTAB
//   }     // while nextscn
//   return 0;
// }

#endif /* PLUGINS_NEW */
