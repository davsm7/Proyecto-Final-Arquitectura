module ALU #(
    parameter SIZEDATA = 32,
    OP = 4
) (
    input [SIZEDATA-1 : 0] a,
    input [SIZEDATA-1 : 0] b,
    input [OP-1 : 0] operador,
    output reg zero,
    output reg [SIZEDATA-1 : 0] resultado
);

  always @* begin
    resultado = 32'b0;
    zero = 0;
    case (operador)
      4'b0000: begin
        resultado = a & b;
      end
      4'b0001: begin
        resultado = a | b;
      end
      4'b0010: begin
        resultado = a + b;
      end
      4'b0110: begin
        resultado = a - b;
        zero = (resultado == 0) ? 1 : 0;
      end
      4'b0111: begin
        resultado = a < b ? 1 : 0;
      end
      4'b1100: begin
        resultado = ~a || ~b;
      end
      default: begin
        resultado = 32'b0;
        zero = 0;
      end
    endcase
  end


endmodule
