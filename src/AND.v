module AND(
	input A,
	input B,
	output res

);



assign res = A & B ? 1 : 0;

endmodule