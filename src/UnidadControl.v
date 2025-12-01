module Control(
    input [5:0] instruccion,
    output reg RegDest,
    output reg Branch,
    output reg MemRead,
    output reg MemtoReg,
    output reg [1:0] ALUOp,
    output reg MemWrite,
    output reg ALUSrc,
    output reg RegWrite,
    output reg Jump,
    output reg is_byte,
    output reg is_unsigned
);
    
    always @(*) begin
        // Valores por defecto
        RegDest = 1'b0;
        Branch = 1'b0;
        MemRead = 1'b0;
        MemtoReg = 1'b0;
        ALUOp = 2'b00;  // Por defecto
        MemWrite = 1'b0;
        ALUSrc = 1'b0;
        RegWrite = 1'b0;
        Jump = 1'b0;
        is_byte = 1'b0;
        is_unsigned = 1'b0;
        
        case (instruccion)
            // Instrucciones tipo R
            6'b000000: begin // R-format
                RegDest = 1'b1;
                RegWrite = 1'b1;
                ALUOp = 2'b10;  // 10 para R-type
            end
            
            // LW - Load Word
            6'b100011: begin
                ALUSrc = 1'b1;
                MemtoReg = 1'b1;
                RegWrite = 1'b1;
                MemRead = 1'b1;
                ALUOp = 2'b00;  // 00 para add
            end
            
            // SW - Store Word  
            6'b101011: begin
                ALUSrc = 1'b1;
                MemWrite = 1'b1;
                ALUOp = 2'b00;  // 00 para add
            end
            
            // LB - Load Byte
            6'b100000: begin
                MemRead = 1'b1;
                MemtoReg = 1'b1;
                ALUSrc = 1'b1;
                RegWrite = 1'b1;
                is_byte = 1'b1;
                is_unsigned = 1'b1;
                ALUOp = 2'b00;  // 00 para add
            end
            
            // SB - Store Byte
            6'b101000: begin
                MemWrite = 1'b1;
                ALUSrc = 1'b1;
                is_byte = 1'b1;
                is_unsigned = 1'b1;
                ALUOp = 2'b00;  // 00 para add
            end
            
            // BEQ - Branch Equal
            6'b000100: begin
                Branch = 1'b1;
                ALUOp = 2'b01;  // ← 01 para branches!
            end
            
            // BNE - Branch Not Equal ← ¡AGREGAR!
            6'b000101: begin
                Branch = 1'b1;
                ALUOp = 2'b01;  // ← 01 para branches!
            end
            
            // J - Jump
            6'b000010: begin
                Jump = 1'b1;
            end
            
            // ADDI - Add Immediate
            6'b001000: begin
                ALUSrc = 1'b1;
                RegWrite = 1'b1;
                ALUOp = 2'b00;  // 00 para add
            end
            
            // ANDI - And Immediate
            6'b001100: begin
                ALUSrc = 1'b1;
                RegWrite = 1'b1;
                ALUOp = 2'b11;  // 11 para lógicas
            end
            
            // ORI - Or Immediate
            6'b001101: begin
                ALUSrc = 1'b1;
                RegWrite = 1'b1;
                ALUOp = 2'b11;  // 11 para lógicas
            end
            
            default: begin
                // Ninguna operación
            end
        endcase
    end
endmodule