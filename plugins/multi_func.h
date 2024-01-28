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

#ifdef PLUGINS_NEW

#include <llvm-c-15/llvm-c/Core.h>
#include <llvm-c-15/llvm-c/Error.h>
#include <llvm-c-15/llvm-c/ExecutionEngine.h>
#include <llvm-c-15/llvm-c/Orc.h>
#include <llvm-c-15/llvm-c/OrcEE.h>
#include <llvm-c-15/llvm-c/Target.h>
#include <llvm-c-15/llvm-c/TargetMachine.h>
#include <llvm-c-15/llvm-c/Types.h>

#include "dbm.h"

#include <pthread.h>

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

#endif /* PLUGINS_NEW */
