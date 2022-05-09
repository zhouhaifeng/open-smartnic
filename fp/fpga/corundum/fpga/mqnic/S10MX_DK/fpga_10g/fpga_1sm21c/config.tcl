# Copyright 2021, The Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS OF THE UNIVERSITY OF CALIFORNIA ''AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS OF THE UNIVERSITY OF CALIFORNIA OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of The Regents of the University of California.

set params [dict create]

# collect build information
set build_date [clock seconds]
set git_hash 00000000
set git_tag ""

if { [catch {set git_hash [exec git rev-parse --short=8 HEAD]}] } {
    puts "Error running git or project not under version control"
}

if { [catch {set git_tag [exec git describe --tags HEAD]}] } {
    puts "Error running git, project not under version control, or no tag found"
}

puts "Build date: ${build_date}"
puts "Git hash: ${git_hash}"
puts "Git tag: ${git_tag}"

if { ! [regsub {^.*(\d+\.\d+\.\d+([\.-]\d+)?).*$} $git_tag {\1} tag_ver ] } {
    puts "Failed to extract version from git tag"
    set tag_ver 0.0.1
}

puts "Tag version: ${tag_ver}"

# FW and board IDs
set fpga_id [expr 0x432AC0DD]
set fw_id [expr 0x00000000]
set fw_ver $tag_ver
set board_vendor_id [expr 0x1172]
set board_device_id [expr 0x0001]
set board_ver 1.0
set release_info [expr 0x00000000]

# PCIe IDs
set pcie_vendor_id [expr 0x1234]
set pcie_device_id [expr 0x1001]
set pcie_class_code [expr 0x020000]
set pcie_revision_id [expr 0x00]
set pcie_subsystem_vendor_id $board_vendor_id
set pcie_subsystem_device_id $board_device_id

dict set params FPGA_ID [format "32'h%08x" $fpga_id]
dict set params FW_ID [format "32'h%08x" $fw_id]
dict set params FW_VER [format "32'h%02x%02x%02x%02x" {*}[split $fw_ver .-] 0 0 0 0]
dict set params BOARD_ID [format "32'h%04x%04x" $board_vendor_id $board_device_id]
dict set params BOARD_VER [format "32'h%02x%02x%02x%02x" {*}[split $board_ver .-] 0 0 0 0]
dict set params BUILD_DATE  "32'd${build_date}"
dict set params GIT_HASH  "32'h${git_hash}"
dict set params RELEASE_INFO  [format "32'h%08x" $release_info]

# Structural configuration

#  counts    QSFP 0                                QSFP 1
# IF  PORT   0_1      0_2      0_3      0_4        1_1      1_2      1_3      1_4
# 1   1      0 (0.0)
# 1   2      0 (0.0)  1 (0.1)
# 1   3      0 (0.0)  1 (0.1)  2 (0.2)
# 1   4      0 (0.0)  1 (0.1)  2 (0.2)  3 (0.3)
# 1   5      0 (0.0)  1 (0.1)  2 (0.2)  3 (0.3)    4 (0.4)
# 1   6      0 (0.0)  1 (0.1)  2 (0.2)  3 (0.3)    4 (0.4)  5 (0.5)
# 1   7      0 (0.0)  1 (0.1)  2 (0.2)  3 (0.3)    4 (0.4)  5 (0.5)  6 (0.6)
# 1   8      0 (0.0)  1 (0.1)  2 (0.2)  3 (0.3)    4 (0.4)  5 (0.5)  6 (0.6)  7 (0.7)
# 2   1      0 (0.0)                               1 (1.0)
# 2   2      0 (0.0)  1 (0.1)                      2 (1.0)  3 (1.1)
# 2   3      0 (0.0)  1 (0.1)  2 (0.2)             3 (1.0)  4 (1.1)  5 (1.2)
# 2   4      0 (0.0)  1 (0.1)  2 (0.2)  3 (0.3)    4 (1.0)  5 (1.1)  6 (1.2)  7 (1.3)
# 3   1      0 (0.0)  1 (1.0)  2 (2.0)
# 3   2      0 (0.0)  1 (0.1)  2 (1.0)  3 (1.1)    4 (2.0)  5 (2.1)
# 4   1      0 (0.0)  1 (1.0)  2 (2.0)  3 (3.0)
# 4   2      0 (0.0)  1 (0.1)  2 (1.0)  3 (1.1)    4 (2.0)  5 (2.1)  6 (3.0)  7 (3.1)
# 5   1      0 (0.0)  1 (1.0)  2 (2.0)  3 (3.0)    4 (4.0)
# 6   1      0 (0.0)  1 (1.0)  2 (2.0)  3 (3.0)    4 (4.0)  5 (5.0)
# 7   1      0 (0.0)  1 (1.0)  2 (2.0)  3 (3.0)    4 (4.0)  5 (5.0)  6 (6.0)
# 8   1      0 (0.0)  1 (1.0)  2 (2.0)  3 (3.0)    4 (4.0)  5 (5.0)  6 (6.0)  7 (7.0)

dict set params IF_COUNT "2"
dict set params PORTS_PER_IF "1"
dict set params SCHED_PER_IF [dict get $params PORTS_PER_IF]

# PTP configuration
dict set params PTP_CLOCK_PIPELINE "0"
dict set params PTP_PORT_CDC_PIPELINE "0"
dict set params PTP_PEROUT_ENABLE "1"
dict set params PTP_PEROUT_COUNT "1"

# Queue manager configuration (interface)
dict set params EVENT_QUEUE_OP_TABLE_SIZE "32"
dict set params TX_QUEUE_OP_TABLE_SIZE "32"
dict set params RX_QUEUE_OP_TABLE_SIZE "32"
dict set params TX_CPL_QUEUE_OP_TABLE_SIZE [dict get $params TX_QUEUE_OP_TABLE_SIZE]
dict set params RX_CPL_QUEUE_OP_TABLE_SIZE [dict get $params RX_QUEUE_OP_TABLE_SIZE]
dict set params EVENT_QUEUE_INDEX_WIDTH "5"
dict set params TX_QUEUE_INDEX_WIDTH "10"
dict set params RX_QUEUE_INDEX_WIDTH "8"
dict set params TX_CPL_QUEUE_INDEX_WIDTH [dict get $params TX_QUEUE_INDEX_WIDTH]
dict set params RX_CPL_QUEUE_INDEX_WIDTH [dict get $params RX_QUEUE_INDEX_WIDTH]
dict set params EVENT_QUEUE_PIPELINE "3"
dict set params TX_QUEUE_PIPELINE [expr 3+([dict get $params TX_QUEUE_INDEX_WIDTH] > 12 ? [dict get $params TX_QUEUE_INDEX_WIDTH]-12 : 0)]
dict set params RX_QUEUE_PIPELINE [expr 3+([dict get $params RX_QUEUE_INDEX_WIDTH] > 12 ? [dict get $params RX_QUEUE_INDEX_WIDTH]-12 : 0)]
dict set params TX_CPL_QUEUE_PIPELINE [dict get $params TX_QUEUE_PIPELINE]
dict set params RX_CPL_QUEUE_PIPELINE [dict get $params RX_QUEUE_PIPELINE]

# TX and RX engine configuration (port)
dict set params TX_DESC_TABLE_SIZE "32"
dict set params RX_DESC_TABLE_SIZE "32"

# Scheduler configuration (port)
dict set params TX_SCHEDULER_OP_TABLE_SIZE [dict get $params TX_DESC_TABLE_SIZE]
dict set params TX_SCHEDULER_PIPELINE [dict get $params TX_QUEUE_PIPELINE]
dict set params TDMA_INDEX_WIDTH "6"

# Timestamping configuration (port)
dict set params PTP_TS_ENABLE "1"
dict set params TX_PTP_TS_FIFO_DEPTH "32"
dict set params RX_PTP_TS_FIFO_DEPTH "32"

# Interface configuration (port)
dict set params TX_CHECKSUM_ENABLE "1"
dict set params RX_RSS_ENABLE "1"
dict set params RX_HASH_ENABLE "1"
dict set params RX_CHECKSUM_ENABLE "1"
dict set params TX_FIFO_DEPTH "32768"
dict set params RX_FIFO_DEPTH "32768"
dict set params MAX_TX_SIZE "9214"
dict set params MAX_RX_SIZE "9214"
dict set params TX_RAM_SIZE "32768"
dict set params RX_RAM_SIZE "32768"

# Application block configuration
dict set params APP_ENABLE "0"
dict set params APP_CTRL_ENABLE "1"
dict set params APP_DMA_ENABLE "1"
dict set params APP_AXIS_DIRECT_ENABLE "1"
dict set params APP_AXIS_SYNC_ENABLE "1"
dict set params APP_AXIS_IF_ENABLE "1"
dict set params APP_STAT_ENABLE "1"

# DMA interface configuration
dict set params DMA_LEN_WIDTH "16"
dict set params DMA_TAG_WIDTH "16"
dict set params RAM_ADDR_WIDTH [expr int(ceil(log(max([dict get $params TX_RAM_SIZE], [dict get $params RX_RAM_SIZE]))/log(2)))]
dict set params RAM_PIPELINE "2"

# PCIe interface configuration
dict set params SEG_COUNT "1"
dict set params SEG_DATA_WIDTH "256"
dict set params SEG_EMPTY_WIDTH [expr int(ceil(log([dict get $params SEG_DATA_WIDTH]/32.0)/log(2)))]
dict set params TX_SEQ_NUM_WIDTH "6"
dict set params PCIE_TAG_COUNT "256"
dict set params PCIE_DMA_READ_OP_TABLE_SIZE [dict get $params PCIE_TAG_COUNT]
dict set params PCIE_DMA_READ_TX_LIMIT "16"
dict set params PCIE_DMA_READ_TX_FC_ENABLE "1"
dict set params PCIE_DMA_WRITE_OP_TABLE_SIZE "16"
dict set params PCIE_DMA_WRITE_TX_LIMIT "3"
dict set params PCIE_DMA_WRITE_TX_FC_ENABLE "1"

# AXI lite interface configuration (control)
dict set params AXIL_CTRL_DATA_WIDTH "32"
dict set params AXIL_CTRL_ADDR_WIDTH "24"

# AXI lite interface configuration (application control)
dict set params AXIL_APP_CTRL_DATA_WIDTH [dict get $params AXIL_CTRL_DATA_WIDTH]
dict set params AXIL_APP_CTRL_ADDR_WIDTH "24"

# Ethernet interface configuration
dict set params AXIS_ETH_TX_PIPELINE "0"
dict set params AXIS_ETH_TX_FIFO_PIPELINE "2"
dict set params AXIS_ETH_TX_TS_PIPELINE "0"
dict set params AXIS_ETH_RX_PIPELINE "0"
dict set params AXIS_ETH_RX_FIFO_PIPELINE "2"

# Statistics counter subsystem
dict set params STAT_ENABLE "0"
dict set params STAT_DMA_ENABLE "1"
dict set params STAT_PCIE_ENABLE "1"
dict set params STAT_INC_WIDTH "24"
dict set params STAT_ID_WIDTH "12"

# PCIe IP core settings
set pcie pcie_s10_hip_ast_0
set pcie_ip pcie
set fp [open "update_ip_${pcie_ip}.tcl" "w"]

puts $fp "package require qsys"
puts $fp "load_system ip/${pcie_ip}.ip"

puts $fp "set_instance_parameter_value ${pcie} {pf0_pci_type0_device_id_hwtcl} {$pcie_device_id}"
puts $fp "set_instance_parameter_value ${pcie} {pf0_pci_type0_vendor_id_hwtcl} {$pcie_vendor_id}"
puts $fp "set_instance_parameter_value ${pcie} {pf0_class_code_hwtcl} {$pcie_class_code}"
puts $fp "set_instance_parameter_value ${pcie} {pf0_revision_id_hwtcl} {$pcie_revision_id}"
puts $fp "set_instance_parameter_value ${pcie} {pf0_subsys_dev_id_hwtcl} {$pcie_subsystem_device_id}"
puts $fp "set_instance_parameter_value ${pcie} {pf0_subsys_vendor_id_hwtcl} {$pcie_subsystem_vendor_id}"

# configure BAR settings
proc configure_bar {fp pcie pf bar aperture} {
    if {$aperture > 0} {
        puts "PF${pf} BAR${bar}: aperture ${aperture} bits"

        puts $fp "set_instance_parameter_value ${pcie} {pf${pf}_bar${bar}_address_width_hwtcl} {${aperture}}"
        puts $fp "set_instance_parameter_value ${pcie} {pf${pf}_bar${bar}_type_hwtcl} {64-bit prefetchable memory}"

        return
    }
    puts "PF${pf} BAR${bar}: disabled"

    puts $fp "set_instance_parameter_value ${pcie} {pf${pf}_bar${bar}_address_width_hwtcl} {0}"
    puts $fp "set_instance_parameter_value ${pcie} {pf${pf}_bar${bar}_type_hwtcl} {Disabled}"
}

# Control BAR (BAR 0)
configure_bar $fp $pcie 0 0 [dict get $params AXIL_CTRL_ADDR_WIDTH]

# Application BAR (BAR 2)
configure_bar $fp $pcie 0 2 [expr [dict get $params APP_ENABLE] ? [dict get $params AXIL_APP_CTRL_ADDR_WIDTH] : 0]

puts $fp "save_system"
close $fp

# apply parameters to PCIe IP core
exec -ignorestderr qsys-script "--qpf=fpga.qpf" "--script=update_ip_${pcie_ip}.tcl"

# apply parameters to top-level
dict for {name value} $params {
    set_parameter -name $name $value
}
