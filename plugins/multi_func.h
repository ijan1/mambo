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

#include "dbm.h"

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <pthread.h>
#include <stdint.h>

#include <llvm-c-15/llvm-c/Core.h>

#define BLACK_FG "\x1b[30m"
#define RED_FG "\x1b[31m"
#define GREEN_FG "\x1b[32m"
#define YELLOW_FG "\x1b[33m"
#define BLUE_FG "\x1b[34m"
#define PURPLE_FG "\x1b[35m"
#define CYAN_FG "\x1b[36m"
#define WHITE_FG "\x1b[37m"
#define BOLD_FG "\x1b[1m"
#define UNDERLINE_FG "\x1b[4m"
#define CLEAR "\x1b[0m"

#if defined(MJAO)
#define MAMBO_LOG(format, ...)                                                 \
  do {                                                                         \
    fprintf(stdout, BLUE_FG "[MAMBO] " CLEAR format, ##__VA_ARGS__);           \
  } while (0)
#else
#define MAMBO_LOG(format, ...)                                                 \
  do {                                                                         \
  } while (0)
#endif

#define LLVM_ERR(format, ...)                                                  \
  do {                                                                         \
    fprintf(stderr, RED_FG "[MAMBO_LLVM] " CLEAR format, ##__VA_ARGS__);       \
    LLVMDisposeMessage(error);                                                 \
    error = NULL;                                                              \
    return 1;                                                                  \
  } while (0)

typedef struct {
  uint64_t regs[32];
  uint64_t pc;

  bool should_swap;
  bool is_morello;
} CPU_t;

void initialise_cpu(CPU_t *this) {
  for(int i = 0; i < 32; i++) {
    this->regs[i] = 0xDEADBEEF;
  }

  this->pc = 0xDEADBEEF;

  this->should_swap = false;
  this->is_morello = false;
}

void handle_parameter(mambo_context *ctx, LLVMTypeKind param, size_t param_idx);

#endif /* PLUGINS_NEW */
