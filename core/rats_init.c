/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#include <string.h>
#include <librats/log.h>
#include <librats/err.h>
#include "librats/attester.h"
#include <internal/attester.h>
#include "librats/verifier.h"
#include <internal/verifier.h>
#include <internal/core.h>

#ifdef SGX
#include "rats_t.h"
#endif

#ifdef SGX
#define RATS_ATTESTER_NUM	3
#define RATS_VERIFIER_NUM	4
#define RATS_NAME   		32
// clang-format on
char rats_attester_name[RATS_ATTESTER_NUM][RATS_NAME] = { "nullattester", "sgx_la", "sgx_ecdsa" };
char rats_verifier_name[RATS_VERIFIER_NUM][RATS_NAME] = { "nullverifier", "sgx_la", "sgx_ecdsa",
							  "sgx_ecdsa_qve" };
#endif

rats_attester_err_t rats_attest_init(rats_conf_t *conf, rats_core_context_t *ctx)
{
	RATS_DEBUG("called\n");

	char attester_type[32] = "nullattester";

	rats_global_log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
	if (rats_global_log_level == (rats_log_level_t)-1) {
		RATS_FATAL("failed to get log level from env\n");
		rats_exit();
	}

	rats_global_core_context.config.api_version = RATS_API_VERSION_DEFAULT;
	rats_global_core_context.config.log_level = rats_global_log_level;

	if (!conf)
		return RATS_ATTESTER_ERR_INVALID;

	RATS_DEBUG("conf %p\n", conf);

	if (!ctx)
		return RATS_ATTESTER_ERR_NO_MEM;

	ctx->config = *conf;

	rats_attester_err_t err = RATS_ATTESTER_ERR_INVALID;

	if (ctx->config.api_version > RATS_API_VERSION_MAX) {
		RATS_ERR("unsupported rats api version %d > %d\n", ctx->config.api_version,
			 RATS_API_VERSION_MAX);
		goto err_ctx;
	}

	if (ctx->config.log_level < 0 || ctx->config.log_level >= RATS_LOG_LEVEL_MAX) {
		ctx->config.log_level = rats_global_core_context.config.log_level;
		RATS_WARN("log level reset to global value %d\n",
			  rats_global_core_context.config.log_level);
	}

	rats_global_log_level = ctx->config.log_level;

	if (rats_attester_nums == 0) {
#ifdef SGX
		for (uint8_t i = 0; i < RATS_ATTESTER_NUM; i++) {
			err = rats_attester_init(rats_attester_name[i], NULL, NULL);
			if (err != RATS_ATTESTER_ERR_NONE) {
				RATS_ERR("failed to initialize rats instance: %s\n",
					 rats_attester_name[i]);
				rats_exit();
			}
		}
#else
		/* Load all rats attester instances */
		err = rats_attester_load_all();
		if (err != RATS_ATTESTER_ERR_NONE) {
			RATS_FATAL("failed to load any rats attester %#x\n", err);
			rats_exit();
		}
#endif
	}
// clang-format off
#if defined(SGX) || defined(OCCLUM)
	memset(attester_type, 0, 32);
#ifdef SGX_ECDSA
	memcpy(attester_type, "sgx_ecdsa", 32);
#elif defined(SGX_LA)
	memcpy(attester_type, "sgx_la", 32);
#endif
#else
	memcpy(attester_type, rats_attesters_ctx[0]->opts->name, 32);
	if (rats_global_core_context.config.attester_type[0] != '\0')
		memcpy(attester_type, rats_global_core_context.config.attester_type, 32);
#endif
// clang-format on

	err = rats_attester_select(ctx, attester_type);
	if (err != RATS_ATTESTER_ERR_NONE)
		goto err_ctx;

err_ctx:
	return err;
}

rats_verifier_err_t rats_verify_init(rats_conf_t *conf, rats_core_context_t *ctx)
{
	RATS_DEBUG("called\n");

	char *choice = NULL;
	rats_global_log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
	if (rats_global_log_level == (rats_log_level_t)-1) {
		RATS_FATAL("failed to get log level from env\n");
		rats_exit();
	}

	rats_global_core_context.config.api_version = RATS_API_VERSION_DEFAULT;
	rats_global_core_context.config.log_level = rats_global_log_level;

	if (!conf)
		return RATS_VERIFIER_ERR_INVALID;

	RATS_DEBUG("conf %p\n", conf);

	if (!ctx)
		return RATS_VERIFIER_ERR_NO_MEM;

	ctx->config = *conf;

	rats_verifier_err_t err = RATS_VERIFIER_ERR_INVALID;

	if (ctx->config.api_version > RATS_API_VERSION_MAX) {
		RATS_ERR("unsupported rats api version %d > %d\n", ctx->config.api_version,
			 RATS_API_VERSION_MAX);
		goto err_ctx;
	}

	if (ctx->config.log_level < 0 || ctx->config.log_level >= RATS_LOG_LEVEL_MAX) {
		ctx->config.log_level = rats_global_core_context.config.log_level;
		RATS_WARN("log level reset to global value %d\n",
			  rats_global_core_context.config.log_level);
	}

	rats_global_log_level = ctx->config.log_level;
	if (rats_verifier_nums == 0) {
#ifdef SGX
		for (uint8_t i = 0; i < RATS_VERIFIER_NUM; i++) {
			err = rats_verifier_init(rats_verifier_name[i], NULL, NULL);
			if (err != RATS_VERIFIER_ERR_NONE) {
				RATS_ERR("failed to initialize rats instance %s %#x\n",
					 rats_verifier_name[i], err);
				rats_exit();
			}
		}
#else
		/* Load all rats verifier instances */
		err = rats_verifier_load_all();
		if (err != RATS_VERIFIER_ERR_NONE) {
			RATS_FATAL("failed to load any rats verifier %#x\n", err);
			rats_exit();
		}
#endif
	}
	/* Select the target verifier to be used */
	choice = ctx->config.verifier_type;
	if (choice[0] == '\0') {
		choice = rats_global_core_context.config.verifier_type;
		if (choice[0] == '\0')
			choice = "nullverifier";
	}
	err = rats_verifier_select(ctx, choice);
	if (err != RATS_VERIFIER_ERR_NONE)
		goto err_ctx;

err_ctx:
	return err;
}
