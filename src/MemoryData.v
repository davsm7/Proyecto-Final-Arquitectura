module memoriaDatos #(
    parameter SIZE = 32,
    parameter SIZE_MEM = 32'h7FF,
    parameter SIZE_WORD_MEM = 8
)(
    input [SIZE-1:0] address,
    input [SIZE-1:0] dato,
    input MemWrite,
    input MemRead,
    input is_byte,           // 0=word, 1=byte
    output reg [SIZE-1:0] datoLeido
);

    reg [SIZE_WORD_MEM-1:0] memory [SIZE_MEM-1:0];
	
	initial begin
		$readmemb("Storange.txt", memory);
	end
    
    // ESCRIBIR - PURO BIG ENDIAN
    always @(*) begin
        if (MemWrite === 1'b1 && address < SIZE_MEM) begin
            if (is_byte) begin
                // sb - Store Byte
                memory[address] <= dato[31:24];  // Siempre los bits 31:24 para bytes
            end else begin
                // sw - Store Word - BIG ENDIAN
                if (address < (SIZE_MEM - 3)) begin
                    memory[address]   <= dato[31:24];  // Byte más significativo
                    memory[address+1] <= dato[23:16];
                    memory[address+2] <= dato[15:8];
                    memory[address+3] <= dato[7:0];   // Byte menos significativo
                end
            end
        end
    end
    
    // LEER - PURO BIG ENDIAN
    always @(*) begin
        if (MemRead === 1'b1 && address < SIZE_MEM) begin
            if (is_byte) begin
                // lb - Load Byte (sin signo como quieres)
                datoLeido = {24'b0, memory[address]};
            end else begin
                // lw - Load Word - BIG ENDIAN
                if (address < (SIZE_MEM - 3)) begin
                    datoLeido = {memory[address],   memory[address+1],
                                 memory[address+2], memory[address+3]};
                end else begin
                    datoLeido = 32'h00000000;
                end
            end
        end else begin
            datoLeido = 32'h00000000;
        end
    end

endmodule