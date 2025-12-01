module MEM_WB#(parameter S_WB = 2,
			   parameter SIZE_DATA = 32,
			   parameter SIZE_ADDR = 5)
	(
		input clk,
		input [S_WB-1:0] WB,
		input [SIZE_DATA-1:0] DatoLeido,
		input [SIZE_DATA-1:0] direccion,
		input [SIZE_ADDR-1:0] direccionRegistro,
		output reg [S_WB-1:0] WB_out,
		output reg [SIZE_DATA-1:0] datoLeido_out,
		output reg [SIZE_DATA-1:0] direccion_out,
		output reg [SIZE_ADDR-1:0] direccionRegistro_out
	);
	
	always @(posedge clk) begin
	
		WB_out <= WB;
		datoLeido_out <= DatoLeido;
		direccion_out <= direccion;
		direccionRegistro_out <= direccionRegistro;
	
	end
	
endmodule
