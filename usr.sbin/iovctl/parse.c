/*-
 * Copyright (c) 2013 Sandvine Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/iov.h>
#include <net/ethernet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <nv.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <ucl.h>
#include <unistd.h>

#include "iovctl.h"

static void
report_config_error(const char *key, const ucl_object_t *obj, const char *type)
{

	errx(EX_DATAERR, "Value '%s' of key '%s' is not of type %s",
	    ucl_object_tostring(obj), key, type);
}

/*
 * Verifies that the value specified in the config file is a boolean value, and
 * then adds the value to the configuration.
 */
static void
add_bool_config(const char *key, const ucl_object_t *obj, nvlist_t *config)
{
	bool val;

	if (!ucl_object_toboolean_safe(obj, &val))
		report_config_error(key, obj, "bool");

	nvlist_add_bool(config, key, val);
}

/*
 * Verifies that the value specified in the config file is a unicast MAC
 * address, and then adds the value to the configuration.
 */
static void
add_mac_addr_config(const char *key, const ucl_object_t *obj, nvlist_t *config)
{
	uint8_t mac[ETHER_ADDR_LEN];
	const char *val, *token;
	char *parse, *orig_parse, *tokpos, *endpos;
	u_long value;
	int i;

	if (!ucl_object_tostring_safe(obj, &val))
		report_config_error(key, obj, "mac-addr");

	parse = strdup(val);
	orig_parse = parse;

	i = 0;
	while ((token = strtok_r(parse, ":", &tokpos)) != NULL) {
		parse = NULL;

		if (*token == '\0')
			report_config_error(key, obj, "mac-addr");

		value = strtoul(token, &endpos, 16);

		if (*endpos != '\0')
			report_config_error(key, obj, "mac-addr");

		if (value > UINT8_MAX)
			report_config_error(key, obj, "mac-addr");

		if (i >= ETHER_ADDR_LEN)
			report_config_error(key, obj, "mac-addr");

		mac[i] = value;
		i++;
	}

	free(orig_parse);

	if (i != ETHER_ADDR_LEN)
		report_config_error(key, obj, "mac-addr");

	nvlist_add_binary(config, key, mac, ETHER_ADDR_LEN);
}

/*
 * Verifies that the value specified in the config file is a string, and then
 * adds the value to the configuration.
 */
static void
add_string_config(const char *key, const ucl_object_t *obj, nvlist_t *config)
{
	const char *val;

	if (!ucl_object_tostring_safe(obj, &val))
		report_config_error(key, obj, "string");

	nvlist_add_string(config, key, val);
}

/*
 * Verifies that the value specified in the config file is a integer value
 * within the specified range, and then adds the value to the configuration.
 *
 * Note that I have to use a (signed) intmax_t here because libucl only converts
 * values to signed integers.
 */
static void
add_uint_config(const char *key, const ucl_object_t *obj, nvlist_t *config,
    const char *type, intmax_t max)
{
	int64_t val;

	if (!ucl_object_toint_safe(obj, &val))
		report_config_error(key, obj, type);

	if (val > max)
		report_config_error(key, obj, type);

	nvlist_add_number(config, key, val);
}

/*
 * Validates that the given configuation value has the right type as specified
 * in the schema, and then adds the value to the configuation node.
 */
static void
add_config(const char *key, const ucl_object_t *obj, nvlist_t *config,
    const nvlist_t *schema)
{
	const char *type;

	type = nvlist_get_string(schema, TYPE_SCHEMA_NAME);

	if (strcasecmp(type, "bool") == 0)
		add_bool_config(key, obj, config);
	else if (strcasecmp(type, "mac-addr") == 0)
		add_mac_addr_config(key, obj, config);
	else if (strcasecmp(type, "string") == 0)
		add_string_config(key, obj, config);
	else if (strcasecmp(type, "uint8_t") == 0)
		add_uint_config(key, obj, config, type, UINT8_MAX);
	else if (strcasecmp(type, "uint16_t") == 0)
		add_uint_config(key, obj, config, type, UINT16_MAX);
	else if (strcasecmp(type, "uint32_t") == 0)
		add_uint_config(key, obj, config, type, UINT32_MAX);
	else if (strcasecmp(type, "uint64_t") == 0)
		add_uint_config(key, obj, config, type, UINT64_MAX);
	else
		errx(EX_SOFTWARE, "Unexpected type '%s' in schema", type);
}

/*
 * Parses all values specified in a device section in the configuration file,
 * validates that the key/value pair is valid in the schema, and then adds
 * the key/value pair to the correct subsystem in the config.
 */
static void
parse_device_config(const ucl_object_t *top, nvlist_t *config,
    const char *subsystem, const nvlist_t *schema)
{
	ucl_object_iter_t it;
	const ucl_object_t *obj;
	nvlist_t *subsystem_config, *driver_config, *iov_config;
	const nvlist_t *driver_schema, *iov_schema;
	const char *key;

	if (nvlist_exists(config, subsystem))
		errx(EX_DATAERR, "Multiple definitions of '%s' in config file",
		    subsystem);

	driver_schema = nvlist_get_nvlist(schema, DRIVER_CONFIG_NAME);
	iov_schema = nvlist_get_nvlist(schema, IOV_CONFIG_NAME);

	driver_config = nvlist_create(NV_FLAG_IGNORE_CASE);
	if (driver_config == NULL)
		err(EX_OSERR, "Could not allocate config nvlist");

	iov_config = nvlist_create(NV_FLAG_IGNORE_CASE);
	if (iov_config == NULL)
		err(EX_OSERR, "Could not allocate config nvlist");

	subsystem_config = nvlist_create(NV_FLAG_IGNORE_CASE);
	if (subsystem_config == NULL)
		err(EX_OSERR, "Could not allocate config nvlist");

	it = NULL;
	while ((obj = ucl_iterate_object(top, &it, true)) != NULL) {
		key = ucl_object_key(obj);

		if (nvlist_exists_nvlist(iov_schema, key))
			add_config(key, obj, iov_config,
			    nvlist_get_nvlist(iov_schema, key));
		else if (nvlist_exists_nvlist(driver_schema, key))
			add_config(key, obj, driver_config,
			    nvlist_get_nvlist(driver_schema, key));
		else
			errx(EX_DATAERR, "PF: Invalid config key '%s'", key);
	}

	nvlist_move_nvlist(subsystem_config, DRIVER_CONFIG_NAME, driver_config);
	nvlist_move_nvlist(subsystem_config, IOV_CONFIG_NAME, iov_config);
	nvlist_move_nvlist(config, subsystem, subsystem_config);
}

/*
 * Parses the specified config file using the given schema, and returns an
 * nvlist containing the configuration specified by the file.
 *
 * Exits with an message to stderr and an error if any config validation fails.
 */
nvlist_t *
parse_config_file(const char *filename, const nvlist_t *schema)
{
	ucl_object_iter_t it;
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *obj;
	nvlist_t *config;
	const nvlist_t *pf_schema, *vf_schema;
	const char *errmsg, *key;
	regex_t vf_pat;
	int regex_err;

	regex_err = regcomp(&vf_pat, "^"VF_PREFIX"([0-9]+)$",
	    REG_EXTENDED | REG_ICASE);

	if (regex_err != 0)
		errx(EX_SOFTWARE, "Could not compile VF regex");

	parser = ucl_parser_new(0);

	if (parser == NULL)
		err(EX_OSERR, "Could not allocate parser");

	if (!ucl_parser_add_file(parser, filename))
		err(EX_NOINPUT, "Could not open '%s' for reading", filename);

	errmsg = ucl_parser_get_error(parser);
	if (errmsg != NULL)
		errx(EX_DATAERR, "Could not parse config file: %s", errmsg);

	config = nvlist_create(NV_FLAG_IGNORE_CASE);

	if (config == NULL)
		err(EX_OSERR, "Could not allocate config nvlist");

	pf_schema = nvlist_get_nvlist(schema, PF_CONFIG_NAME);
	vf_schema = nvlist_get_nvlist(schema, VF_SCHEMA_NAME);

	top = ucl_parser_get_object (parser);
	it = NULL;
	while ((obj = ucl_iterate_object(top, &it, true)) != NULL) {
		key = ucl_object_key(obj);

		if (strcasecmp(key, PF_CONFIG_NAME) == 0)
			parse_device_config(obj, config, key, pf_schema);
		else if(strcasecmp(key, DEFAULT_SCHEMA_NAME) == 0)
			parse_device_config(obj, config, key, vf_schema);
		else if(regexec(&vf_pat, key, 0, NULL, 0) == 0)
			parse_device_config(obj, config, key, vf_schema);
		else
			errx(EX_DATAERR, "Unexpected top-level node: %s", key);
	}

	validate_config(config, schema, &vf_pat);

	ucl_object_unref(top);
	ucl_parser_free(parser);
	regfree(&vf_pat);

	return (config);
}

/*
 * Parse the PF configuration section for and return the value specified for
 * the device parameter, or NULL if the device is not specified.
 */
static const char *
find_pf_device(const ucl_object_t *pf)
{
	ucl_object_iter_t it;
	const ucl_object_t *obj;
	const char *key, *device;

	it = NULL;
	while ((obj = ucl_iterate_object(pf, &it, true)) != NULL) {
		key = ucl_object_key(obj);

		if (strcasecmp(key, "device") == 0) {
			if (!ucl_object_tostring_safe(obj, &device))
				err(EX_DATAERR,
				    "Config PF.device must be a string");

			return (device);
		}
	}

	return (NULL);
}

/*
 * Manually parse the config file looking for the name of the PF device.  We
 * have to do this separately because we need the config schema to call the
 * normal config file parsing code, and we need to know the name of the PF
 * device so that we can fetch the schema from it.
 *
 * This will always exit on failure, so if it returns then it is guaranteed to
 * have returned a valid device name.
 */
char *
find_device(const char *filename)
{
	char *device;
	const char *deviceName;
	ucl_object_iter_t it;
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *obj;
	const char *errmsg, *key;
	int error;

	device = NULL;

	parser = ucl_parser_new(0);

	if (parser == NULL)
		err(EX_OSERR, "Could not allocate parser");

	if (!ucl_parser_add_file(parser, filename))
		err(EX_NOINPUT, "Could not open '%s' for reading", filename);

	errmsg = ucl_parser_get_error(parser);
	if (errmsg != NULL)
		errx(EX_DATAERR, "Could not parse config file: %s", errmsg);

	top = ucl_parser_get_object (parser);
	it = NULL;
	while ((obj = ucl_iterate_object(top, &it, true)) != NULL) {
		key = ucl_object_key(obj);

		if (strcasecmp(key, PF_CONFIG_NAME) == 0)
			deviceName = find_pf_device(obj);
	}

	if (deviceName == NULL)
		errx(EX_DATAERR, "Config file does not specify device");

	error = asprintf(&device, "/dev/iov/%s", deviceName);

	if (error < 0)
		err(EX_OSERR, "Could not allocate memory for device");

	ucl_object_unref(top);
	ucl_parser_free(parser);

	return (device);
}
