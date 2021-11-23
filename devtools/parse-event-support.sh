#! /bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

# Parse event dev support of a driver directory,
# and optionally show difference with a doc file in .ini format.

dir=$1 # drivers/event/foo
ref=$2 # doc/guides/eventdevs/features/foo.ini

if [ -z "$dir" ]; then
	echo "directory argument is required" >&2
	exit 1
fi

# sorting order
export LC_COLLATE=C

check_rx_adptr_sw_capa()
{
	driver=$(echo "$dir" | cut -d / -f 3)
	if [ "$driver" = "dsw" ] || [ "$driver" = "sw" ] ; then
		return 1
	else
		return 0
	fi
}

# generate INI section
list() # <title> <pattern> <extra_patterns>
{
	echo "[$1]"
	word0=$(git grep -who "$2[[:alnum:]_]*" $dir)
	word1=$(echo "$3")
	words="$word0""$word1"
	echo "$words" | sort -u |
		awk 'sub(/'$2'/, "") {printf "%-20s = Y\n", tolower($0)}'
}

event_dev_sched_support()
{
	title="Scheduling Features"
	pattern=$(echo "RTE_EVENT_DEV_CAP_" | awk '{print toupper($0)}')
	list "$title" "$pattern" ""
}

event_dev_rx_adptr_support()
{
	title="Eth Rx adapter Features"
	pattern=$(echo "RTE_EVENT_ETH_RX_ADAPTER_CAP_" |
		awk '{print toupper($0)}')
	check_rx_adptr_sw_capa || extra='RTE_EVENT_ETH_RX_ADAPTER_CAP_OVERRIDE_FLOW_ID
				RTE_EVENT_ETH_RX_ADAPTER_CAP_MULTI_EVENTQ
				RTE_EVENT_ETH_RX_ADAPTER_CAP_EVENT_VECTOR'
	list "$title" "$pattern" "$extra"
}

event_dev_tx_adptr_support()
{
	title="Eth Tx adapter Features"
	pattern=$(echo "RTE_EVENT_ETH_TX_ADAPTER_CAP_" |
		awk '{print toupper($0)}')
	list "$title" "$pattern" ""
}

event_dev_crypto_adptr_support()
{
	title="Crypto adapter Features"
	pattern=$(echo "RTE_EVENT_CRYPTO_ADAPTER_CAP_" |
		awk '{print toupper($0)}')
	list "$title" "$pattern" ""
}

event_dev_timer_adptr_support()
{
	title="Timer adapter Features"
	pattern=$(echo "RTE_EVENT_TIMER_ADAPTER_CAP_" |
		awk '{print toupper($0)}')
	list "$title" "$pattern" ""
}

if [ -z "$ref" ]; then # generate full tables
	event_dev_sched_support
	echo
	event_dev_rx_adptr_support
	echo
	event_dev_tx_adptr_support
	echo
	event_dev_crypto_adptr_support
	echo
	event_dev_timer_adptr_support
	exit 0
fi

# compare with reference input
event_dev_sched_compare()
{
	section="Scheduling Features]"
	{
		event_dev_sched_support
		sed -n "/$section/,/]/p" "$ref" | sed '/^$/d'
	} |
	sed '/]/d' | # ignore section title
	sed 's, *=.*,,' | # ignore value (better in doc than generated one)
	sort | uniq -u | # show differences
	sed "s,^,Scheduling Features ," # prefix with category name
}

event_dev_rx_adptr_compare()
{
	section="Eth Rx adapter Features]"
	{
		event_dev_rx_adptr_support
		sed -n "/$section/,/]/p" "$ref" | sed '/^$/d'
	} |
	sed '/]/d' | # ignore section title
	sed 's, *=.*,,' | # ignore value (better in doc than generated one)
	sort | uniq -u | # show differences
	sed "s,^,Eth Rx adapter Features ," # prefix with category name
}

event_dev_tx_adptr_compare()
{
	section="Eth Tx adapter Features]"
	{
		event_dev_tx_adptr_support
		sed -n "/$section/,/]/p" "$ref" | sed '/^$/d'
	} |
	sed '/]/d' | # ignore section title
	sed 's, *=.*,,' | # ignore value (better in doc than generated one)
	sort | uniq -u | # show differences
	sed "s,^,Eth Tx adapter Features ," # prefix with category name
}

event_dev_crypto_adptr_compare()
{
	section="Crypto adapter Features]"
	{
		event_dev_crypto_adptr_support
		sed -n "/$section/,/]/p" "$ref" | sed '/^$/d'
	} |
	sed '/]/d' | # ignore section title
	sed 's, *=.*,,' | # ignore value (better in doc than generated one)
	sort | uniq -u | # show differences
	sed "s,^,Crypto adapter Features ," # prefix with category name
}

event_dev_timer_adptr_compare()
{
	section="Timer adapter Features]"
	{
		event_dev_timer_adptr_support
		sed -n "/$section/,/]/p" "$ref" | sed '/^$/d'
	} |
	sed '/]/d' | # ignore section title
	sed 's, *=.*,,' | # ignore value (better in doc than generated one)
	sort | uniq -u | # show differences
	sed "s,^,Timer adapter Features ," # prefix with category name
}

event_dev_sched_compare
event_dev_rx_adptr_compare
event_dev_tx_adptr_compare
event_dev_crypto_adptr_compare
event_dev_timer_adptr_compare
