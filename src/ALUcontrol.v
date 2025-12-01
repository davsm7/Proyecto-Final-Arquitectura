module ALUcontrol
	#(parameter SIZEOP = 6,
	  parameter SIZE_ALU_OP = 2,
	  parameter S_ALU = 4)
	(
	input[SIZEOP-1:0] instruccion,
	input [SIZE_ALU_OP-1:0] AluOP,
	output reg[S_ALU-1:0] outInst
);


always @* begin
	case(AluOP)	
		2'b10:
		begin
			case(instruccion)
			6'b100000:
			begin
				outInst = 4'b0010;
			end
			6'b100010:
			begin
				outInst = 4'b0110;
			end
			6'b100100:
			begin
				outInst = 4'b0000;
			end
			6'b100101:
			begin
				outInst = 4'b0001;
			end
			6'b101010:
			begin
				outInst = 4'b0111;
			end
		endcase
		end
		2'b00:
		begin
			//outInst = 6'b100011;
			//outInst = 6'b101011;
			outInst = 4'b0010;
		end
		2'b01:
		begin
			//outInst = 6'b000100;
			outInst = 4'b0110;
		end
	
	endcase
end

endmodule