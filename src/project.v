/*
 * Copyright (c) 2026 ED
 * SPDX-License-Identifier: Apache-2.0
 */

// Tiny Tapeout AES-128 example
// SPDX-License-Identifier: Apache-2.0
//
// Interface protocol:
//   uio_in = 8'h01: load one key byte from ui_in (16 bytes, MSB first)
//   uio_in = 8'h02: load one plaintext byte from ui_in (16 bytes, MSB first)
//   uio_in = 8'h03: start encryption (pulse for one clock)
//   uio_in = 8'h04: read one ciphertext byte from uo_out (16 bytes, MSB first)
//   uio_in = 8'h05: read status on uo_out; bit 0 = busy, bit 1 = done
//
// Ciphertext output is read one byte at a time with command 8'h04.
// This is an educational synthesizable implementation. Run the Tiny Tapeout
// synthesis/physical-design flow to determine whether it fits the chosen tile.

`default_nettype none

module tt_um_aes128 (
    input  wire [7:0] ui_in,
    output reg  [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

    localparam [7:0] CMD_LOAD_KEY   = 8'h01;
    localparam [7:0] CMD_LOAD_PT    = 8'h02;
    localparam [7:0] CMD_START      = 8'h03;
    localparam [7:0] CMD_READ_CT    = 8'h04;
    localparam [7:0] CMD_STATUS     = 8'h05;

    reg [127:0] key_reg;
    reg [127:0] plaintext_reg;
    reg [3:0] key_index;
    reg [3:0] pt_index;
    reg [3:0] ct_index;
    reg start_reg;

    wire [127:0] ciphertext;
    wire busy;
    wire done;

    assign uio_out = 8'h00;
    assign uio_oe  = 8'h00; // Bidirectional pins are inputs.

    aes128_core core (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (start_reg),
        .key         (key_reg),
        .plaintext   (plaintext_reg),
        .ciphertext  (ciphertext),
        .busy        (busy),
        .done        (done)
    );

    always @* begin
        uo_out = 8'h00;
        case (uio_in)
            CMD_READ_CT: uo_out = ciphertext[127 - (ct_index * 8) -: 8];
            CMD_STATUS:  uo_out = {6'b000000, done, busy};
            default:     uo_out = 8'h00;
        endcase
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg       <= 128'h0;
            plaintext_reg <= 128'h0;
            key_index     <= 4'd0;
            pt_index      <= 4'd0;
            ct_index      <= 4'd0;
            start_reg     <= 1'b0;
        end else begin
            start_reg <= 1'b0;

            case (uio_in)
                CMD_LOAD_KEY: begin
                    key_reg[127 - (key_index * 8) -: 8] <= ui_in;
                    if (key_index == 4'd15)
                        key_index <= 4'd0;
                    else
                        key_index <= key_index + 1'b1;
                end

                CMD_LOAD_PT: begin
                    plaintext_reg[127 - (pt_index * 8) -: 8] <= ui_in;
                    if (pt_index == 4'd15)
                        pt_index <= 4'd0;
                    else
                        pt_index <= pt_index + 1'b1;
                end

                CMD_START: begin
                    start_reg <= 1'b1;
                    ct_index  <= 4'd0;
                end

                CMD_READ_CT: begin
                    if (ct_index == 4'd15)
                        ct_index <= 4'd0;
                    else
                        ct_index <= ct_index + 1'b1;
                end

                default: begin
                    // No operation.
                end
            endcase
        end
    end

    // ena is part of the standard Tiny Tapeout interface. This design does
    // not use it internally.
    wire unused_ena = ena;

endmodule


module aes128_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] key,
    input  wire [127:0] plaintext,
    output reg  [127:0] ciphertext,
    output reg          busy,
    output reg          done
);

    reg [127:0] state_reg;
    reg [127:0] round_key;
    reg [3:0] round_num;

    wire [127:0] next_round_key;
    wire [127:0] sub_shift_state;
    wire [127:0] round_state;

    assign next_round_key = expand_key(round_key, round_num);
    assign sub_shift_state = sub_bytes_shift_rows(state_reg);
    assign round_state =
        ((round_num == 4'd10) ? sub_shift_state : mix_columns(sub_shift_state))
        ^ next_round_key;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_reg  <= 128'h0;
            round_key  <= 128'h0;
            ciphertext <= 128'h0;
            round_num  <= 4'd0;
            busy       <= 1'b0;
            done       <= 1'b0;
        end else begin
            done <= 1'b0;

            if (start && !busy) begin
                state_reg <= plaintext ^ key;
                round_key <= key;
                round_num <= 4'd1;
                busy      <= 1'b1;
            end else if (busy) begin
                state_reg <= round_state;
                round_key <= next_round_key;

                if (round_num == 4'd10) begin
                    ciphertext <= round_state;
                    busy       <= 1'b0;
                    done       <= 1'b1;
                    round_num  <= 4'd0;
                end else begin
                    round_num <= round_num + 1'b1;
                end
            end
        end
    end

    function automatic [7:0] gf_mul;
        input [7:0] a;
        input [7:0] b;
        reg [7:0] aa;
        reg [7:0] bb;
        reg [7:0] p;
        integer i;
        begin
            aa = a;
            bb = b;
            p  = 8'h00;
            for (i = 0; i < 8; i = i + 1) begin
                if (bb[0])
                    p = p ^ aa;
                if (aa[7])
                    aa = (aa << 1) ^ 8'h1b;
                else
                    aa = aa << 1;
                bb = bb >> 1;
            end
            gf_mul = p;
        end
    endfunction

    // AES S-box: multiplicative inverse in GF(2^8), followed by the
    // standard affine transformation. The loops have fixed bounds.
    function automatic [7:0] aes_sbox;
        input [7:0] a;
        reg [7:0] base;
        reg [7:0] result;
        reg [7:0] exponent;
        reg [7:0] x;
        integer i;
        begin
            base = a;
            result = 8'h01;
            exponent = 8'd254;
            for (i = 0; i < 8; i = i + 1) begin
                if (exponent[i])
                    result = gf_mul(result, base);
                base = gf_mul(base, base);
            end
            x = result;
            aes_sbox = x
                     ^ {x[6:0], x[7]}
                     ^ {x[5:0], x[7:6]}
                     ^ {x[4:0], x[7:5]}
                     ^ {x[3:0], x[7:4]}
                     ^ 8'h63;
        end
    endfunction

    function automatic [127:0] sub_bytes_shift_rows;
        input [127:0] state_in;
        reg [127:0] result;
        integer i;
        integer row;
        integer col;
        integer source_index;
        begin
            result = 128'h0;
            // AES state is represented column-major: byte index = 4*col+row.
            for (i = 0; i < 16; i = i + 1) begin
                col = i / 4;
                row = i % 4;
                source_index = 4 * ((col + row) % 4) + row;
                result[127 - (i * 8) -: 8] =
                    aes_sbox(state_in[127 - (source_index * 8) -: 8]);
            end
            sub_bytes_shift_rows = result;
        end
    endfunction

    function automatic [7:0] xtime;
        input [7:0] a;
        begin
            if (a[7])
                xtime = (a << 1) ^ 8'h1b;
            else
                xtime = a << 1;
        end
    endfunction

    function automatic [127:0] mix_columns;
        input [127:0] state_in;
        reg [127:0] result;
        reg [7:0] a0;
        reg [7:0] a1;
        reg [7:0] a2;
        reg [7:0] a3;
        integer c;
        begin
            result = 128'h0;
            for (c = 0; c < 4; c = c + 1) begin
                a0 = state_in[127 - ((4*c+0)*8) -: 8];
                a1 = state_in[127 - ((4*c+1)*8) -: 8];
                a2 = state_in[127 - ((4*c+2)*8) -: 8];
                a3 = state_in[127 - ((4*c+3)*8) -: 8];

                result[127 - ((4*c+0)*8) -: 8] =
                    xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
                result[127 - ((4*c+1)*8) -: 8] =
                    a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
                result[127 - ((4*c+2)*8) -: 8] =
                    a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
                result[127 - ((4*c+3)*8) -: 8] =
                    (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
            end
            mix_columns = result;
        end
    endfunction

    function automatic [127:0] expand_key;
        input [127:0] key_in;
        input [3:0] round_in;
        reg [7:0] rcon;
        reg [31:0] temp;
        reg [31:0] w0;
        reg [31:0] w1;
        reg [31:0] w2;
        reg [31:0] w3;
        begin
            case (round_in)
                4'd1:  rcon = 8'h01;
                4'd2:  rcon = 8'h02;
                4'd3:  rcon = 8'h04;
                4'd4:  rcon = 8'h08;
                4'd5:  rcon = 8'h10;
                4'd6:  rcon = 8'h20;
                4'd7:  rcon = 8'h40;
                4'd8:  rcon = 8'h80;
                4'd9:  rcon = 8'h1b;
                4'd10: rcon = 8'h36;
                default: rcon = 8'h00;
            endcase

            temp = {
                aes_sbox(key_in[23:16]) ^ rcon,
                aes_sbox(key_in[15:8]),
                aes_sbox(key_in[7:0]),
                aes_sbox(key_in[31:24])
            };

            w0 = key_in[127:96] ^ temp;
            w1 = key_in[95:64]  ^ w0;
            w2 = key_in[63:32]  ^ w1;
            w3 = key_in[31:0]   ^ w2;
            expand_key = {w0, w1, w2, w3};
        end
    endfunction

endmodule

`default_nettype wire

