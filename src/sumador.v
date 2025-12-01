module sumador #
	(parameter SIZE =8)
	(
	input[SIZE-1:0] A,
	input[SIZE-1:0] B,
	output [SIZE-1:0] res
	);
	
	

	assign res = A + B;
	
endmodule