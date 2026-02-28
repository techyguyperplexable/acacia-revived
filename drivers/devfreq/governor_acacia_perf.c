// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/devfreq/governor_acacia_perf.c
 *
 * Devfreq governor that locks device frequency to maximum.
 * Handles start and resume events to ensure frequency is
 * re-applied after suspend cycles.
 *
 * Copyright (C) 2024 Acacia
 */

#include <linux/devfreq.h>
#include <linux/module.h>
#include "governor.h"

static int devfreq_acacia_perf_func(struct devfreq *df,
				    unsigned long *freq)
{
	*freq = DEVFREQ_MAX_FREQ;
	return 0;
}

static int devfreq_acacia_perf_handler(struct devfreq *devfreq,
				unsigned int event, void *data)
{
	int ret = 0;

	switch (event) {
	case DEVFREQ_GOV_START:
	case DEVFREQ_GOV_RESUME:
		mutex_lock(&devfreq->lock);
		ret = update_devfreq(devfreq);
		mutex_unlock(&devfreq->lock);
		break;
	case DEVFREQ_GOV_STOP:
	case DEVFREQ_GOV_SUSPEND:
		break;
	default:
		break;
	}

	return ret;
}

static struct devfreq_governor devfreq_acacia_perf = {
	.name = "acacia_perf",
	.immutable = 0,
	.get_target_freq = devfreq_acacia_perf_func,
	.event_handler = devfreq_acacia_perf_handler,
};

static int __init devfreq_acacia_perf_init(void)
{
	return devfreq_add_governor(&devfreq_acacia_perf);
}
subsys_initcall(devfreq_acacia_perf_init);

static void __exit devfreq_acacia_perf_exit(void)
{
	int ret;

	ret = devfreq_remove_governor(&devfreq_acacia_perf);
	if (ret)
		pr_err("%s: failed remove governor %d\n", __func__, ret);
}
module_exit(devfreq_acacia_perf_exit);

MODULE_AUTHOR("techyguyperplexable <objecting@objecting.org>");
MODULE_DESCRIPTION("Acacia Devfreq Performance Governor - Maximum device frequency");
MODULE_LICENSE("GPL");
