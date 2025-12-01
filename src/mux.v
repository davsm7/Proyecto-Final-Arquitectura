module MUX
	#(parameter SIZE = 32)
	(
	input[SIZE-1:0] dato,
	input[SIZE-1:0] dato2,
	input sel,
	output reg[SIZE-1:0] datoOut
);


always @* begin
	case(sel)
		1'b1:
		begin	
			datoOut = dato;
		end
		1'b0:
		begin
			datoOut = dato2;
		end
	endcase
end


endmodule