#!/bin/bash
# ==============================================================================
# File Name:     monitor.sh
# Author:        Eva Tate and Giselle Wu, assisted by Claude Code
# Course:        CS60: Computer Networks
# Assignment:    Lab 4: Physical layer - Radio Signal Strength
# Date:          October 23, 2026
#
# Description:   Puts a Wi-Fi adapter into monitor mode on a given channel and
#                prints the interface info so the user can confirm.
#                Usage: sudo ./monitor.sh <interface> <channel>
#
# ==============================================================================

if [ "$#" -ne 2 ]; then
    echo "Usage: sudo $0 <interface> <channel>" >&2
    exit 1
fi
if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root (use sudo)" >&2
    exit 1
fi

IFACE="$1"
CHANNEL="$2"

ip link set "$IFACE" down                  || exit 1
iw dev "$IFACE" set type monitor           || exit 1
ip link set "$IFACE" up                    || exit 1
iw dev "$IFACE" set channel "$CHANNEL"     || exit 1

# Confirm: should show "type monitor" and "channel <N>"
iw dev "$IFACE" info
