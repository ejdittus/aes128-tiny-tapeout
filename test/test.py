# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, FallingEdge, Timer

KEY = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
PLAINTEXT = bytes.fromhex('00112233445566778899aabbccddeeff')
EXPECTED = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')

async def command(dut, cmd, data=0):
    await FallingEdge(dut.clk)
    dut.uio_in.value = cmd
    dut.ui_in.value = data
    await ClockCycles(dut.clk, 1)
    # Clear command before next rising edge to avoid repeating a transfer.
    await FallingEdge(dut.clk)
    dut.uio_in.value = 0

@cocotb.test()
async def aes128_nist_known_answer(dut):
    cocotb.start_soon(Clock(dut.clk, 10, unit='ns').start())
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 4)
    await FallingEdge(dut.clk)
    dut.rst_n.value = 1

    for b in KEY:
        await command(dut, 1, b)
    for b in PLAINTEXT:
        await command(dut, 2, b)
    await command(dut, 3)

    # The core raises done for one cycle; sample every cycle.
    done = False
    for _ in range(30):
        await FallingEdge(dut.clk)
        dut.uio_in.value = 5
        await Timer(1, unit='ns')
        status = int(dut.uo_out.value)
        if status & 2:
            done = True
            break
    assert done, 'AES did not complete within 30 cycles'

    # With command 4 asserted, output is the current indexed byte.
    # Sample before each rising edge; that edge advances the index.
    result = []
    await FallingEdge(dut.clk)
    dut.uio_in.value = 4
    for _ in range(16):
        await Timer(1, unit='ns')
        result.append(int(dut.uo_out.value))
        await ClockCycles(dut.clk, 1)
        await FallingEdge(dut.clk)
    dut.uio_in.value = 0

    assert bytes(result) == EXPECTED, (
        f'Got {bytes(result).hex()}, expected {EXPECTED.hex()}')
