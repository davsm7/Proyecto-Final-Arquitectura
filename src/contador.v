module PC
	#(parameter S_DATA = 32)
	(
    input clk,
    input reset,
    input [S_DATA-1:0] pc_in,
    output reg [S_DATA-1:0] pc_out
);

always @(posedge clk or posedge reset) begin
    if (reset) begin
        pc_out <= 32'b0; // Reset PC to 0
    end else begin
        pc_out <= pc_in; // Update PC with input value
    end
end

endmodule