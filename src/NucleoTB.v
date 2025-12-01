`timescale 1ns / 1ps
module coreTB();


	parameter CLK_PERIOD = 10; // 10 ns = 100 MHz
	parameter ADDRESS_INSTRUCCION = 32;

	reg clk;
	reg [ADDRESS_INSTRUCCION-1:0] pc_in;
	reg reset_pc;
	
	NucleoTop DUT(
		.clk(clk),
		.pc_in(pc_in),
		.reset_pc(reset_pc)
	);
	

	initial clk = 1'b0;
		
	always #(CLK_PERIOD/2.0)begin
	
		clk = ~clk;
	end
	
	initial 
	begin
		reset_pc = 1'b1;
		pc_in = 32'b0;
		#(CLK_PERIOD*3);

		reset_pc = 1'b0;
		#100;
			
		#100;
	end
	

endmodule
