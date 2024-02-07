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

#include "plugins.h"
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <pthread.h>
#include <stdint.h>

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

#define MAMBO_ERR(format, ...)                                                  \
  do {                                                                         \
    fprintf(stderr, RED_FG "[MAMBO] " CLEAR format, ##__VA_ARGS__);       \
    LLVMDisposeMessage(error);                                                 \
    error = NULL;                                                              \
  } while (0)

#endif /* PLUGINS_NEW */
