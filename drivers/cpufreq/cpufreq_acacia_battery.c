// SPDX-License-Identifier: GPL-2.0
/*
 * CPUFreq governor: acacia-battery
 *
 * Locks CPU frequency to the policy minimum.
 *
 * Copyright (C) 2024 techyguyperplexable
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/module.h>

static int cpufreq_gov_acacia_battery_start(struct cpufreq_policy *policy)
{
	pr_debug("setting policy%u to %u kHz\n", policy->cpu, policy->min);
	__cpufreq_driver_target(policy, policy->min, CPUFREQ_RELATION_L);
	return 0;
}

static void cpufreq_gov_acacia_battery_limits(struct cpufreq_policy *policy)
{
	pr_debug("updating policy%u to %u kHz\n", policy->cpu, policy->min);
	__cpufreq_driver_target(policy, policy->min, CPUFREQ_RELATION_L);
}

static struct cpufreq_governor cpufreq_gov_acacia_battery = {
	.name		= "acacia-battery",
	.start		= cpufreq_gov_acacia_battery_start,
	.limits		= cpufreq_gov_acacia_battery_limits,
	.owner		= THIS_MODULE,
};

static int __init cpufreq_gov_acacia_battery_register(void)
{
	return cpufreq_register_governor(&cpufreq_gov_acacia_battery);
}

static void __exit cpufreq_gov_acacia_battery_unregister(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_acacia_battery);
}

MODULE_AUTHOR("techyguyperplexable <objecting@objecting.org>");
MODULE_DESCRIPTION("Acacia Battery Governor - Minimum frequency for maximum battery life");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ACACIA_BATTERY
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &cpufreq_gov_acacia_battery;
}
#endif

fs_initcall(cpufreq_gov_acacia_battery_register);
module_exit(cpufreq_gov_acacia_battery_unregister);
