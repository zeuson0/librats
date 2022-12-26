/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#define CSV_DEFAULT_DIR "/opt/csv/"
#define CURL_RETRY_TIMES 5

int get_file_size(char *name);
int read_file(const char *filename, void *buffer, size_t len);
int download_from_url(const char *url, const char *file_path);

void gen_random_bytes(void *buf, size_t len);
int sm3_hash(const unsigned char *data, size_t len, unsigned char *hash, size_t expected_hash_len);
