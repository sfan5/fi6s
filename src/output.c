// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdlib.h>
#include <threads.h>

#include "output.h"
#include "util.h"

struct obuf output_get_scratch_buf(void)
{
	static thread_local char *buf;
	if(!buf)
		buf = calloc(1, OUTPUT_SCRATCH_BUFFER_SIZE);
	// FIXME: how do we free this?
	return (struct obuf) { .buffer = buf, .offset = 0, .size = OUTPUT_SCRATCH_BUFFER_SIZE };
}
