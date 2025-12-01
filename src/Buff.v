module buffer#(parameter SIZE = 32)(
    input clk,
    input [SIZE-1:0] data_in,
    input [SIZE-1:0] data_in2,
    output reg [SIZE-1:0] data_out,
    output reg [SIZE-1:0] data_out2
);

always @(posedge clk) begin
    data_out <= data_in;
    data_out2 <= data_in2;
end

endmodule
