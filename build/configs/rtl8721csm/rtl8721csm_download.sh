#!/usr/bin/env bash
###########################################################################
#
# Copyright 2020 Samsung Electronics All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
###########################################################################
# rtl8721csm_download.sh

if [ -n "$2" ]; then
	PORT="$2"
else
	PORT="ttyUSB1"
fi

WARNING="\n Port $PORT is selected\n\n
	############################################\n
	WARNINGS:\n
	1. Make sure the board is in DOWNLOAD MODE.\n
	2. Make sure NO other application like putty,\n
	is occupying $PORT.\n
	############################################\n"

echo -e $WARNING

CURDIR=$(readlink -f "$0")
CUR_PATH=$(dirname "$CURDIR")
TOOL_PATH=${CUR_PATH}/../../tools/amebad
IMG_TOOL_PATH=${TOOL_PATH}/image_tool
BIN_PATH=${CUR_PATH}/../../output/bin
TOP_PATH=${CUR_PATH}/../../..
OS_PATH=${TOP_PATH}/os
SMARTFS_BIN_PATH=${BIN_PATH}/rtl8721csm_smartfs.bin
FLASH_START_ADDR=0x08000000

TTYDEV="/dev/${PORT}"
CONFIG=${OS_PATH}/.config
source ${CONFIG}

##Utility function for sanity check##
function rtl8721csm_sanity_check()
{
	if [ ! -f ${CONFIG} ];then
		echo "No .config file"
		exit 1
	fi

	if [[ "${CONFIG_ARCH_BOARD_RTL8721CSM}" != "y" ]];then
		echo "Target is NOT RTL8721CSM"
		exit 1
	fi

	if fuser -s ${TTYDEV};then
		echo "${TTYDEV} is used by another process, can't proceed"
		exit 1
	fi
}

##Utility function to match partition name to binary name##
function get_executable_name()
{
	case $1 in
		km0_bl) echo "km0_boot_all.bin";;
		km4_bl) echo "km4_boot_all.bin";;
		kernel|ota) echo "km0_km4_image2.bin";;
		userfs) echo "rtl8721csm_smartfs.bin";;
		*) echo "No Binary Match"
		exit 1
	esac
}
flash_ota=false
##Utility function to get partition index ##
function get_partition_index()
{
	for idx in ${!parts[@]}; do
		if [[ ${parts[$idx],,} == ${1,,} ]]; then
			if [[ $flash_ota == true ]]; then
				## In this case, try to find 2nd kernel partition for OTA
				flash_ota=false
				continue;
			fi
			echo $idx
			exit 1
		fi
	done
	echo -1
}

##Help utility##
function rtl8721csm_dwld_help()
{
        cat <<EOF
	HELP:
		make download ALL or [PARTITION(S)]
	PARTITION(S):
		 [${uniq_parts[@]}]  NOTE:case sensitive

	For examples:
		make download ALL
	        make download kernel
		make download ota
	        make download smartfs
EOF
}

##Utility function to read partitions from .config or Kconfig##
function get_configured_partitions()
{
	local configured_parts
	# Read Partitions
	if [[ -z ${CONFIG_FLASH_PART_NAME} ]];then

		configured_parts=`grep -A 2 'config FLASH_PART_NAME' ${PARTITION_KCONFIG} | sed -n 's/\tdefault "\(.*\)".*/\1/p'`
	else
		configured_parts=${CONFIG_FLASH_PART_NAME}
	fi

	echo $configured_parts
}

##Utility function to get the partition sizes from .config or Kconfig
function get_partition_sizes()
{
	local sizes_str
	#Read Partition Sizes
	if [[ -z ${CONFIG_FLASH_PART_SIZE} ]]
	then
		sizes_str=`grep -A 2 'config FLASH_PART_SIZE' ${PARTITION_KCONFIG} | sed -n 's/\tdefault "\(.*\)".*/\1/p'`
	else
		sizes_str=${CONFIG_FLASH_PART_SIZE}
	fi

	echo $sizes_str
}

# Start here

cp -p ${BIN_PATH}/km0_boot_all.bin ${IMG_TOOL_PATH}/km0_boot_all.bin
cp -p ${BIN_PATH}/km4_boot_all.bin ${IMG_TOOL_PATH}/km4_boot_all.bin
cp -p ${BIN_PATH}/km0_km4_image2.bin ${IMG_TOOL_PATH}/km0_km4_image2.bin
if test -f "${SMARTFS_BIN_PATH}"; then
	cp -p ${BIN_PATH}/rtl8721csm_smartfs.bin ${IMG_TOOL_PATH}/rtl8721csm_smartfs.bin
fi

rtl8721csm_sanity_check;

parts=$(get_configured_partitions)
IFS=',' read -ra parts <<< "$parts"

sizes=$(get_partition_sizes)
IFS=',' read -ra sizes <<< "$sizes"

#Calculate Flash Offset
num=${#sizes[@]}
offsets[0]=`printf "0x%X" ${FLASH_START_ADDR}`

for (( i=1; i<=$num-1; i++ ))
do
	val=$((sizes[$i-1] * 1024))
	offsets[$i]=`printf "0x%X" $((offsets[$i-1] + ${val}))`
done

#Dump Info
echo ""
echo "==================================================================================="
printf '%b\t\t' "\rPARTITION NAMES: \t${parts[@]}\n"
printf '%b\t\t' "\rPARTITION SIZES: \t${sizes[@]}\n"
printf '%b\t' "\rPARTITION OFFSETS: \t${offsets[@]}\n"
printf "\r"
echo "==================================================================================="
echo ""

if test $# -eq 0; then
	echo "FAIL!! NO Given partition. Refer \"PARTITION NAMES\" above."
	rtl8721csm_dwld_help 1>&2
	exit 1
fi

uniq_parts=($(printf "%s\n" "${parts[@]}" | sort -u));

#Validate arguments
for i in ${cmd_args[@]};do

	if [[ "${i}" == "ALL" ]];then
		continue;
	fi

	for j in ${uniq_parts[@]};do
		if [[ "${i}" == "${j}" ]];then
			result=yes
		fi
	done

	if [[ "$result" != "yes" ]];then
		echo "FAIL!! Given \"${i}\" partition is not available. Refer \"PARTITION NAMES\" above."
		rtl8721csm_dwld_help
		exit 1
	fi
	result=no
done

download_specific_partition()
{
	cd ${IMG_TOOL_PATH}
	TARGET=$1
	if [[ ${TARGET} == "ota" || ${TARGET} == "OTA" ]];then
		TARGET="kernel"
		flash_ota=true
	fi
	partidx=$(get_partition_index ${TARGET})
	if [[ "${partidx}" < 0 ]];then
		echo "Not supported"
		rtl8721csm_dwld_help
		exit 1
	fi

	# Get a filename and Download a file
	echo ""
	echo "============================="
	if [[ $1 == "ota" || $1 == "OTA" ]];then
		echo "Downloading Kernel OTA binary"
	else
		echo "Downloading ${parts[$partidx]} binary"
	fi
	echo "============================="
	exe_name=$(get_executable_name ${parts[$partidx]})
	./amebad_image_tool $TTYDEV 1 ${offsets[$partidx]} ${exe_name}

	echo ""
	echo "Download $exe_name COMPLETE!"

	[ -e ${exe_name} ] && rm ${exe_name}
}

download_all()
{
	cd ${IMG_TOOL_PATH}
	echo "Starting Download..."
	found_kernel=false

	for partidx in ${!parts[@]}; do

		if [[ "${CONFIG_APP_BINARY_SEPARATION}" != "y" ]];then
			if [[ "${parts[$partidx]}" == "userfs" ]];then
				continue
			fi
		fi

		if [[ "${parts[$partidx]}" == "kernel" ]];then
			if [[ $found_kernel == true ]];then
				continue
			fi
			found_kernel=true
		fi

		exe_name=$(get_executable_name ${parts[$partidx]})
		[ "No Binary Match" = "${exe_name}" ] && continue

		echo ""
		echo "=========================="
		echo "Downloading ${parts[$partidx]} binary"
		echo "=========================="

		./amebad_image_tool $TTYDEV 1 ${offsets[$partidx]} ${exe_name}
		rm ${exe_name}

	done
	echo ""
	echo "Download COMPLETE!"
}

case $1 in
	all|ALL)
		download_all
		;;
	*)
		download_specific_partition $1
		;;
esac
