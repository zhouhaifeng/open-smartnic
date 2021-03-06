"""

Copyright (c) 2020 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

import itertools
import logging
import os
import random

import cocotb_test.simulator
import pytest

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer
from cocotb.regression import TestFactory

from cocotbext.axi import AxiLiteBus, AxiLiteMaster


class TB(object):
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.a_clk, 8, units="ns").start())
        cocotb.start_soon(Clock(dut.b_clk, 10, units="ns").start())

        self.axil_master = []

        self.axil_master.append(AxiLiteMaster(AxiLiteBus.from_prefix(dut, "s_axil_a"), dut.a_clk, dut.a_rst))
        self.axil_master.append(AxiLiteMaster(AxiLiteBus.from_prefix(dut, "s_axil_b"), dut.b_clk, dut.b_rst))

    def set_idle_generator(self, generator=None):
        if generator:
            for axil_master in self.axil_master:
                axil_master.write_if.aw_channel.set_pause_generator(generator())
                axil_master.write_if.w_channel.set_pause_generator(generator())
                axil_master.read_if.ar_channel.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            for axil_master in self.axil_master:
                axil_master.write_if.b_channel.set_pause_generator(generator())
                axil_master.read_if.r_channel.set_pause_generator(generator())

    async def cycle_reset(self):
        self.dut.a_rst.setimmediatevalue(0)
        self.dut.b_rst.setimmediatevalue(0)
        await RisingEdge(self.dut.a_clk)
        await RisingEdge(self.dut.a_clk)
        self.dut.a_rst.value = 1
        self.dut.b_rst.value = 1
        await RisingEdge(self.dut.a_clk)
        await RisingEdge(self.dut.a_clk)
        self.dut.a_rst.value = 0
        await RisingEdge(self.dut.b_clk)
        self.dut.b_rst.value = 0
        await RisingEdge(self.dut.a_clk)
        await RisingEdge(self.dut.a_clk)


async def run_test_write(dut, port=0, data_in=None, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    axil_master = tb.axil_master[port]
    byte_lanes = axil_master.write_if.byte_lanes

    await tb.cycle_reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    for length in range(1, byte_lanes*2):
        for offset in range(byte_lanes):
            tb.log.info("length %d, offset %d", length, offset)
            addr = offset+0x1000
            test_data = bytearray([x % 256 for x in range(length)])

            await axil_master.write(addr-4, b'\xaa'*(length+8))

            await axil_master.write(addr, test_data)

            data = await axil_master.read(addr-1, length+2)

            assert data.data == b'\xaa'+test_data+b'\xaa'

    await RisingEdge(dut.a_clk)
    await RisingEdge(dut.a_clk)


async def run_test_read(dut, port=0, data_in=None, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    axil_master = tb.axil_master[port]
    byte_lanes = axil_master.write_if.byte_lanes

    await tb.cycle_reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    for length in range(1, byte_lanes*2):
        for offset in range(byte_lanes):
            tb.log.info("length %d, offset %d", length, offset)
            addr = offset+0x1000
            test_data = bytearray([x % 256 for x in range(length)])

            await axil_master.write(addr, test_data)

            data = await axil_master.read(addr, length)

            assert data.data == test_data

    await RisingEdge(dut.a_clk)
    await RisingEdge(dut.a_clk)


async def run_test_arb(dut, data_in=None, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    await tb.cycle_reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    async def worker(master, offset):
        wr_op = master.init_write(offset, b'\x11\x22\x33\x44')
        rd_op = master.init_read(offset, 4)

        await wr_op.wait()
        await rd_op.wait()

    workers = []

    for k in range(10):
        workers.append(cocotb.start_soon(worker(tb.axil_master[0], k*256)))
        workers.append(cocotb.start_soon(worker(tb.axil_master[1], k*256)))

    while workers:
        await workers.pop(0).join()

    await RisingEdge(dut.a_clk)
    await RisingEdge(dut.a_clk)


async def run_stress_test(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    await tb.cycle_reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    async def worker(master, offset, aperture, count=16):
        for k in range(count):
            length = random.randint(1, min(32, aperture))
            addr = offset+random.randint(0, aperture-length)
            test_data = bytearray([x % 256 for x in range(length)])

            await Timer(random.randint(1, 100), 'ns')

            await master.write(addr, test_data)

            await Timer(random.randint(1, 100), 'ns')

            data = await master.read(addr, length)
            assert data.data == test_data

    workers = []

    for k in range(16):
        workers.append(cocotb.start_soon(worker(tb.axil_master[k%len(tb.axil_master)], k*0x1000, 0x1000, count=16)))

    while workers:
        await workers.pop(0).join()

    await RisingEdge(dut.a_clk)
    await RisingEdge(dut.a_clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


if cocotb.SIM_NAME:

    for test in [run_test_write, run_test_read]:

        factory = TestFactory(test)
        factory.add_option("idle_inserter", [None, cycle_pause])
        factory.add_option("backpressure_inserter", [None, cycle_pause])
        factory.add_option("port", [0, 1])
        factory.generate_tests()

    factory = TestFactory(run_test_arb)
    factory.add_option("idle_inserter", [None, cycle_pause])
    factory.add_option("backpressure_inserter", [None, cycle_pause])
    factory.generate_tests()

    factory = TestFactory(run_stress_test)
    factory.generate_tests()


# cocotb-test

tests_dir = os.path.abspath(os.path.dirname(__file__))
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))


@pytest.mark.parametrize("data_width", [8, 16, 32])
def test_axil_dp_ram(request, data_width):
    dut = "axil_dp_ram"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
    ]

    parameters = {}

    parameters['DATA_WIDTH'] = data_width
    parameters['ADDR_WIDTH'] = 16
    parameters['STRB_WIDTH'] = parameters['DATA_WIDTH'] // 8
    parameters['PIPELINE_OUTPUT'] = 0

    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        parameters=parameters,
        sim_build=sim_build,
        extra_env=extra_env,
    )
