module EX_MEM#(parameter SIZE = 32,
		 parameter ADDR_SIZE = 5,
		 parameter S_WB = 2,
		 parameter S_M = 3)
	(
		input clk,
		input [S_WB-1:0]WB,
		input [S_M-1:0]M,
		input zero_in,
		input [SIZE-1:0] data_in,
		input [SIZE-1:0] data_in2,
		input [SIZE-1:0] AWriteMem_in,
		input [ADDR_SIZE-1:0] AWriteReg_in,
		input is_byte_in,
		output reg [S_WB-1:0] WB_out,
		output reg [S_M-1:0] M_out,
		output reg zero_out,
		output reg [SIZE-1:0] data_out,
		output reg [SIZE-1:0] data_out2,
		output reg [SIZE-1:0] AWriteMem,
		output reg [ADDR_SIZE-1:0] AWriteReg,
		output reg is_byte_out
	);



	always @(posedge clk) begin
		WB_out <= WB;
		M_out <= M;
		data_out <= data_in;
		data_out2 <= data_in2;
		AWriteMem <= AWriteMem_in;
		AWriteReg <= AWriteReg_in;
		is_byte_out <= is_byte_in;
		
	
	end
	


endmodule