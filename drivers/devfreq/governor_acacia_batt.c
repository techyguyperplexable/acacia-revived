// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/devfreq/governor_acacia_batt.c
 *
 * Devfreq governor that locks device frequency to minimum.
 * Handles start and resume events to ensure frequency is
 * re-applied after suspend cycles.
 *
 * Copyright (C) 2024 Acacia
 */

#include <linux/devfreq.h>
#include <linux/module.h>
#include "governor.h"

static int devfreq_acacia_batt_func(struct devfreq *df,
				    unsigned long *freq)
{
	*freq = DEVFREQ_MIN_FREQ;
	return 0;
}

static int devfreq_acacia_batt_handler(struct devfreq *devfreq,
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

static struct devfreq_governor devfreq_acacia_batt = {
	.name = "acacia_batt",
	.immutable = 0,
	.get_target_freq = devfreq_acacia_batt_func,
	.event_handler = devfreq_acacia_batt_handler,
};

static int __init devfreq_acacia_batt_init(void)
{
	return devfreq_add_governor(&devfreq_acacia_batt);
}
subsys_initcall(devfreq_acacia_batt_init);

static void __exit devfreq_acacia_batt_exit(void)
{
	int ret;

	ret = devfreq_remove_governor(&devfreq_acacia_batt);
	if (ret)
		pr_err("%s: failed remove governor %d\n", __func__, ret);
}
module_exit(devfreq_acacia_batt_exit);

MODULE_AUTHOR("techyguyperplexable <objecting@objecting.org>");
MODULE_DESCRIPTION("Acacia Devfreq Battery Governor - Minimum device frequency");
MODULE_LICENSE("GPL");
