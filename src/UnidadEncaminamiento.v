module Forward #(
    parameter SIZE_DATA = 32,
    parameter SIZE_REG = 5,
    parameter SIZE_SEL = 2
)(
    input [SIZE_REG-1:0] in_RS,
    input [SIZE_REG-1:0] in_RT,
    input [SIZE_REG-1:0] in_ex_mem_regRd,
    input [SIZE_REG-1:0] in_mem_wb_regRd,
    input EX_MEM_RegWrite,
    input MEM_WB_RegWrite,
    output reg [SIZE_SEL-1:0] ForwardA,
    output reg [SIZE_SEL-1:0] ForwardB
);

    always @(*) begin
        ForwardA = 2'b00;
        ForwardB = 2'b00;
        
        if (EX_MEM_RegWrite && (in_ex_mem_regRd != 0)) begin
            if (in_ex_mem_regRd == in_RS) begin
                ForwardA = 2'b10;
            end
            if (in_ex_mem_regRd == in_RT) begin
                ForwardB = 2'b10;
            end
        end
        if (MEM_WB_RegWrite && (in_mem_wb_regRd != 0)) begin
            if (!(EX_MEM_RegWrite && (in_ex_mem_regRd != 0) && (in_ex_mem_regRd == in_RS))) begin
                if (in_mem_wb_regRd == in_RS) begin
                    ForwardA = 2'b01;
                end
            end
            if (!(EX_MEM_RegWrite && (in_ex_mem_regRd != 0) && (in_ex_mem_regRd == in_RT))) begin
                if (in_mem_wb_regRd == in_RT) begin
                    ForwardB = 2'b01;
                end
            end
        end
    end

endmodule