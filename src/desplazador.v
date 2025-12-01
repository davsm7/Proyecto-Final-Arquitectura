module desplazar
	#(parameter SIZE=32)
	(
	input [SIZE-1:0] dato,
	output [SIZE-1:0] datoOut
	);
	
	
	assign datoOut = dato >> 2;
	
endmodule
