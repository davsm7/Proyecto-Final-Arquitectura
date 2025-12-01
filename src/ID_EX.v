module ID_EX#(parameter SIZE = 32,
			  parameter ADDR_SIZE = 5,
			  parameter SIZE_FNC = 6,
			  parameter SIZE_EXTEND = 32,
			  parameter S_EX = 4,
			  parameter S_WB =2,
			  parameter S_M = 3)
	(
	input [S_WB-1:0] WB,
	input [S_M-1:0] M,
	input [S_EX-1:0]EX,
    input clk,
    input [SIZE-1:0] data_in,
    input [SIZE-1:0] data_in2,
	input [SIZE_EXTEND-1:0] data_in3,
	input [SIZE-1:0] data_extend_in,
	input [ADDR_SIZE-1:0] if_id_Rs,
	input [ADDR_SIZE-1:0] if_id_Rt,
	input [ADDR_SIZE-1:0] adrWrite1,
	input [ADDR_SIZE-1:0] adrWrite2,
	input [SIZE_FNC-1:0] funcion_in,
	input is_byte_in,
	output reg [S_WB-1:0]WB_out,
	output reg [S_M-1:0]M_out,
	output reg [S_EX-1:0]EX_out,
    output reg [SIZE-1:0] data_out,
    output reg [SIZE-1:0] data_out2,
	output reg [SIZE-1:0] data_out3,
	output reg [SIZE-1:0] data_out_jm,
	output reg [SIZE_FNC-1:0] funcion,
	output reg [ADDR_SIZE-1:0] AWrite1,
	output reg [ADDR_SIZE-1:0] AWrite2,
	output reg [ADDR_SIZE-1:0] Rs,
	output reg [ADDR_SIZE-1:0] Rt,
	output reg is_byte_out
);

always @(posedge clk) begin
    WB_out <= WB;
	M_out <= M;
	EX_out <= EX;
	data_out <= data_in;
    data_out2 <= data_in2;
	data_out3 <= data_in3;
	data_out_jm <= data_extend_in;
	funcion <= funcion_in;
	AWrite1 <= adrWrite1;
	AWrite2 <= adrWrite2;
	Rs <= if_id_Rs;
	Rt <= if_id_Rt;
	is_byte_out <= is_byte_in;
end
endmodule