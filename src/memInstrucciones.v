module memoryInstructions
	#(parameter WORD = 32, S_MEM = 8, DIR_MEM = 1024)
	(
    input [WORD-1:0] address,
    output [WORD-1:0] instruction
);


reg [S_MEM-1:0] memory [0:DIR_MEM-1];

    integer i;
    integer instructions_loaded = 0;

    initial begin
        // Inicializar toda la memoria con 0x00 (NOPs)
        for (i = 0; i < DIR_MEM; i = i + 1) begin
            memory[i] = 8'h00;
        end
		
		$readmemb("Instrucciones.txt", memory);
    
	end

  assign instruction = {memory[address], memory[address+1], memory[address+2], memory[address+3]};
endmodule