module MUX3_1 
#(parameter SIZE = 32,
  parameter SIZE_SEL = 2)
	(
	input [SIZE-1:0] A,
	input [SIZE-1:0] B,
	input [SIZE-1:0] C,
	input [SIZE_SEL-1:0] Forward,
	output reg[SIZE-1:0] dato
);

	always@(*)begin
		case(Forward)
		2'b00:
			begin
				dato = A;
			end
		2'b10:
			begin
				dato = B;
			end
		2'b01:
			begin
				dato = C;
			end
		endcase
	
	
	end

endmodule