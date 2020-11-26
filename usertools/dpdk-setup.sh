#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

#
# Run with "source /path/to/dpdk-setup.sh"
#

#
# Change to DPDK directory ( <this-script's-dir>/.. ), and export it as RTE_SDK
#
cd $(dirname ${BASH_SOURCE[0]})/..
export RTE_SDK=$PWD
echo "------------------------------------------------------------------------------"
echo " RTE_SDK exported as $RTE_SDK"
echo "------------------------------------------------------------------------------"

#
# Sets QUIT variable so script will finish.
#
quit()
{
	QUIT=$1
}

# Shortcut for quit.
q()
{
	quit
}

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
	echo "Unloading any existing DPDK UIO module"
	/sbin/lsmod | grep -s igb_uio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod igb_uio
	fi
}

#
# Unloads VFIO modules.
#
remove_vfio_module()
{
	echo "Unloading any existing VFIO module"
	/sbin/lsmod | grep -s vfio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod vfio-pci
		sudo /sbin/rmmod vfio_iommu_type1
		sudo /sbin/rmmod vfio
	fi
}

#
# Loads new vfio-pci (and vfio module if needed).
#
load_vfio_module()
{
	remove_vfio_module

	VFIO_PATH="kernel/drivers/vfio/pci/vfio-pci.ko*"

	echo "Loading VFIO module"
	/sbin/lsmod | grep -s vfio_pci > /dev/null
	if [ $? -ne 0 ] ; then
		if [ -f /lib/modules/$(uname -r)/$VFIO_PATH ] ; then
			sudo /sbin/modprobe vfio-pci
		fi
	fi

	# make sure regular users can read /dev/vfio
	echo "chmod /dev/vfio"
	sudo chmod a+x /dev/vfio
	if [ $? -ne 0 ] ; then
		echo "FAIL"
		quit
	fi
	echo "OK"

	# check if /dev/vfio/vfio exists - that way we
	# know we either loaded the module, or it was
	# compiled into the kernel
	if [ ! -e /dev/vfio/vfio ] ; then
		echo "## ERROR: VFIO not found!"
	fi
}

#
# Unloads the rte_kni.ko module.
#
remove_kni_module()
{
	echo "Unloading any existing DPDK KNI module"
	/sbin/lsmod | grep -s rte_kni > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod rte_kni
	fi
}

#
# Sets appropriate permissions on /dev/vfio/* files
#
set_vfio_permissions()
{
	# make sure regular users can read /dev/vfio
	echo "chmod /dev/vfio"
	sudo chmod a+x /dev/vfio
	if [ $? -ne 0 ] ; then
		echo "FAIL"
		quit
	fi
	echo "OK"

	# make sure regular user can access everything inside /dev/vfio
	echo "chmod /dev/vfio/*"
	sudo chmod 0666 /dev/vfio/*
	if [ $? -ne 0 ] ; then
		echo "FAIL"
		quit
	fi
	echo "OK"

	# since permissions are only to be set when running as
	# regular user, we only check ulimit here
	#
	# warn if regular user is only allowed
	# to memlock <64M of memory
	MEMLOCK_AMNT=`ulimit -l`

	if [ "$MEMLOCK_AMNT" != "unlimited" ] ; then
		MEMLOCK_MB=`expr $MEMLOCK_AMNT / 1024`
		echo ""
		echo "Current user memlock limit: ${MEMLOCK_MB} MB"
		echo ""
		echo "This is the maximum amount of memory you will be"
		echo "able to use with DPDK and VFIO if run as current user."
		echo -n "To change this, please adjust limits.conf memlock "
		echo "limit for current user."

		if [ $MEMLOCK_AMNT -lt 65536 ] ; then
			echo ""
			echo "## WARNING: memlock limit is less than 64MB"
			echo -n "## DPDK with VFIO may not be able to initialize "
			echo "if run as current user."
		fi
	fi
}

#
# Calls dpdk-devbind.py --status to show the devices and what they
# are all bound to, in terms of drivers.
#
show_devices()
{
	if [ -d /sys/module/vfio_pci -o -d /sys/module/igb_uio ]; then
		${RTE_SDK}/usertools/dpdk-devbind.py --status
	else
		echo "# Please load the 'igb_uio' or 'vfio-pci' kernel module before "
		echo "# querying or adjusting device bindings"
	fi
}

#
# Uses dpdk-devbind.py to move devices to work with vfio-pci
#
bind_devices_to_vfio()
{
	if [ -d /sys/module/vfio_pci ]; then
		${RTE_SDK}/usertools/dpdk-devbind.py --status
		echo ""
		echo -n "Enter PCI address of device to bind to VFIO driver: "
		read PCI_PATH
		sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b vfio-pci $PCI_PATH &&
			echo "OK"
	else
		echo "# Please load the 'vfio-pci' kernel module before querying or "
		echo "# adjusting device bindings"
	fi
}

#
# Uses dpdk-devbind.py to move devices to work with igb_uio
#
bind_devices_to_igb_uio()
{
	if [ -d /sys/module/igb_uio ]; then
		${RTE_SDK}/usertools/dpdk-devbind.py --status
		echo ""
		echo -n "Enter PCI address of device to bind to IGB UIO driver: "
		read PCI_PATH
		sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b igb_uio $PCI_PATH && echo "OK"
	else
		echo "# Please load the 'igb_uio' kernel module before querying or "
		echo "# adjusting device bindings"
	fi
}

#
# Uses dpdk-devbind.py to move devices to work with kernel drivers again
#
unbind_devices()
{
	${RTE_SDK}/usertools/dpdk-devbind.py --status
	echo ""
	echo -n "Enter PCI address of device to unbind: "
	read PCI_PATH
	echo ""
	echo -n "Enter name of kernel driver to bind the device to: "
	read DRV
	sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b $DRV $PCI_PATH && echo "OK"
}

#
# Options for setting up environment.
#
step1_func()
{
	TITLE="Setup linux environment"

	TEXT[1]="Insert VFIO module"
	FUNC[1]="load_vfio_module"

	TEXT[2]="Display current Ethernet/Baseband/Crypto device settings"
	FUNC[2]="show_devices"

	TEXT[3]="Bind Ethernet/Baseband/Crypto device to IGB UIO module"
	FUNC[3]="bind_devices_to_igb_uio"

	TEXT[4]="Bind Ethernet/Baseband/Crypto device to VFIO module"
	FUNC[4]="bind_devices_to_vfio"

	TEXT[5]="Setup VFIO permissions"
	FUNC[5]="set_vfio_permissions"
}

#
# Options for cleaning up the system
#
step2_func()
{
	TITLE="Uninstall and system cleanup"

	TEXT[1]="Unbind devices from IGB UIO or VFIO driver"
	FUNC[1]="unbind_devices"

	TEXT[2]="Remove IGB UIO module"
	FUNC[2]="remove_igb_uio_module"

	TEXT[3]="Remove VFIO module"
	FUNC[3]="remove_vfio_module"

	TEXT[4]="Remove KNI module"
	FUNC[4]="remove_kni_module"
}

STEPS[1]="step1_func"
STEPS[2]="step2_func"

QUIT=0

while [ "$QUIT" == "0" ]; do
	OPTION_NUM=1

	for s in $(seq ${#STEPS[@]}) ; do
		${STEPS[s]}

		echo "----------------------------------------------------------"
		echo " Step $s: ${TITLE}"
		echo "----------------------------------------------------------"

		for i in $(seq ${#TEXT[@]}) ; do
			echo "[$OPTION_NUM] ${TEXT[i]}"
			OPTIONS[$OPTION_NUM]=${FUNC[i]}
			let "OPTION_NUM+=1"
		done

		# Clear TEXT and FUNC arrays before next step
		unset TEXT
		unset FUNC

		echo ""
	done

	echo "[$OPTION_NUM] Exit Script"
	OPTIONS[$OPTION_NUM]="quit"
	echo ""
	echo '--------------------------------------------------'
	echo 'WARNING: This tool will be removed from DPDK 20.11'
	echo '--------------------------------------------------'
	echo
	echo -n "Option: "
	read our_entry
	echo ""
	${OPTIONS[our_entry]} ${our_entry}

	if [ "$QUIT" == "0" ] ; then
		echo
		echo -n "Press enter to continue ..."; read
	fi

done
