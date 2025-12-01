module signed_extention #(
		parameter SIZE_WORD = 32,
		parameter SIZE_HALF_WORD = 16
)(
	input [SIZE_HALF_WORD-1:0] half_word,
	input is_unsigned,
	output reg[SIZE_WORD-1:0] word

);
wire dato_signo = half_word[SIZE_HALF_WORD-1];
wire [SIZE_HALF_WORD-1:0]temp;

assign temp = {16{dato_signo}};


always@(*)begin
	if(is_unsigned)begin
		word = {16'b0, half_word};
	end else begin
		word = {{16{temp}}, half_word};
	end
end


endmodule