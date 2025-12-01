module Registros #(
    parameter S_AD = 5,
    S_DATA = 32,
    DIRECCIONES = 32
) (
    input [S_AD-1:0] ARead1,
    input [S_AD-1:0] ARead2,
    input [S_AD-1:0] AWR,
    input [S_DATA-1:0] DataIn,
    input WE,
    output [S_DATA-1:0] DRead1,
    output [S_DATA-1:0] DRead2
);


  reg [S_DATA-1:0] Registro[0:DIRECCIONES-1];

  initial begin
    $readmemb("Datos.txt", Registro);
  end


  assign DRead1 = Registro[ARead1];
  assign DRead2 = Registro[ARead2];

  always @(*) begin
    if (WE) begin
      Registro[AWR] = DataIn;
    end
  end
endmodule
