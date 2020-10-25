/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2020 Ankur Kothiwal <ankur@freebsd.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ebpf_map.h"
#include "ebpf_allocator.h"
#include "ebpf_util.h"

int hashtable_map_init(struct ebpf_map *, struct ebpf_map_attr *);
int hashtable_map_deinit(struct ebpf_map *);
void *hashtable_map_lookup_elem(struct ebpf_map *, void *);
int hashtable_map_lookup_elem_from_user(struct ebpf_map *, void *, void *);
int hashtable_map_update_elem(struct ebpf_map *, void *, void *, uint64_t );
int hashtable_map_delete_elem(struct ebpf_map *, void *);
int hashtable_map_get_next_key(struct ebpf_map *, void *key,void *);

struct trie_key {
	uint16_t width;
	uint8_t addr[16];
};

static int
lpm_trie_map_init(struct ebpf_map *map, struct ebpf_map_attr *attr)
{
	return hashtable_map_init(map, attr);
}

static void
lpm_trie_map_deinit(struct ebpf_map *map)
{
	hashtable_map_deinit(map);
}

static void *
lpm_trie_map_lookup_elem(struct ebpf_map *map, void *key)
{
	struct trie_key trie_key;
	while(!hashtable_map_lookup_elem(map, key))
	{
		int i = 16;
		trie_key.width = trie_key.width - 8;
		trie_key.addr[i] = 0; 
		i--;
	}
	return hashtable_map_lookup_elem(map, key);
}

static int
lpm_trie_map_lookup_elem_from_user(struct ebpf_map *map, void *key,
		void *value)
{
	struct trie_key trie_key;
	int lookup;
	lookup = hashtable_map_lookup_elem_from_user(map, key, value);
	while(!lookup)
	{
		int i = 16;
		trie_key.width = trie_key.width - 8;
		trie_key.addr[i] = 0; 
		i--;
	}
	return lookup;
}

static int
lpm_trie_map_update_elem(struct ebpf_map *map, void *key, void *value,
		uint64_t flags)
{
	return hashtable_map_update_elem(map, key, value, flags);	
}

static int
lpm_trie_map_delete_elem(struct ebpf_map *map, void *key)
{
	return hashtable_map_delete_elem(map, key);
}

static int
lpm_trie_map_get_next_key(struct ebpf_map *map, void *key, void *next_key)
{
	return hashtable_map_get_next_key(map, key, next_key);
}

const struct ebpf_map_type emt_lpm_trie = {
	.name = "lpm_trie",
	.ops = {
		.init = lpm_trie_map_init,
		.update_elem = lpm_trie_map_update_elem,
		.lookup_elem = lpm_trie_map_lookup_elem,
		.delete_elem = lpm_trie_map_delete_elem,
		.update_elem_from_user = lpm_trie_map_update_elem,
		.lookup_elem_from_user = lpm_trie_map_lookup_elem_from_user,
		.delete_elem_from_user = lpm_trie_map_delete_elem,
		.get_next_key_from_user = lpm_trie_map_get_next_key,
		.deinit = lpm_trie_map_deinit
	}
};
