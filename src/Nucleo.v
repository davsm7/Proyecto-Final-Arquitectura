module NucleoTop#(parameter SIZE_DATA = 32,
				  parameter ADD_INST_SIZE = 32,
				  parameter ADD_SIZE = 32,
				  parameter VALOR_SUMADO = 4,
				  parameter SIZE_OP = 6,
				  parameter SIZE_ADDR_BR = 5,
				  parameter SIZE_FUNC = 6,
				  parameter SIZE_HALF_INST = 16,
				  parameter SIZE_ALU_OP=2,
				  parameter S_OP_ALU = 4,
				  parameter S_WB =2,
				  parameter S_M = 3)
	(
		input clk,
		input [ADD_INST_SIZE-1:0] pc_in,
		input reset_pc
	);
	
	wire [ADD_INST_SIZE-1 : 0] addr_instruccion_in, addr_instruccion_out, addr_instruccion_to_mux;
	wire [SIZE_DATA-1: 0] instruccion_a_buff, out_instruccion;
	wire [ADD_INST_SIZE-1 :0] ID_addr_instruccion_to_EX;
	wire is_byte;
	wire is_byte_id_ex;
	wire is_byte_ex_mem;
	wire is_byte_mem;

	PC #(.S_DATA(ADD_INST_SIZE)) PC(
	  .clk(clk),
	  .reset(reset_pc), 
	  .pc_in(addr_instruccion_to_mux), 
	  .pc_out(addr_instruccion_out)
	);
	
	sumador#(.SIZE(ADD_INST_SIZE)) sumador(
		.A(addr_instruccion_out),
		.B(32'd4),
		.res(addr_instruccion_in)
	);

	memoryInstructions memoryInstructions(
		.address(addr_instruccion_out),
		.instruction(instruccion_a_buff)
	);
	
	IF_ID IF_ID(
		.clk(clk),
		.data_in(instruccion_a_buff),
		.data_in2(addr_instruccion_in),
		.data_out(out_instruccion),
		.data_out2(ID_addr_instruccion_to_EX)
	);
	
	wire [SIZE_OP-1: 0] OP = out_instruccion[31:26];
	wire RegDest;
	wire RegWrite, writeEn;
	wire [SIZE_ALU_OP-1:0] ALUOp;
	wire ALUSrc;
	wire branch;
	wire MemRead;
	wire MemWrite;
	wire Mem_to_Reg;
	wire Jump;
	wire is_unsigned;
	wire WE_encaminamiento = writeEn;
	
	Control Control(
		.instruccion(OP),
		.RegDest(RegDest),
		.Branch(branch),
		.MemRead(MemRead),
		.MemtoReg(Mem_to_Reg),
		.ALUOp(ALUOp),
		.MemWrite(MemWrite),
		.ALUSrc(ALUSrc),
		.RegWrite(RegWrite),
		.Jump(Jump),
		.is_byte(is_byte),
		.is_unsigned(is_unsigned)
	);
	
	wire [SIZE_ADDR_BR-1:0] AR1 = out_instruccion[25:21];
	wire [SIZE_ADDR_BR-1:0] AR2 = out_instruccion[20:16];
	wire [SIZE_ADDR_BR-1:0] IF_ID_RS = out_instruccion[25:21];
	wire [SIZE_ADDR_BR-1:0] IF_ID_RT = out_instruccion[20:16];
	wire [SIZE_ADDR_BR-1:0] AW = out_instruccion[15:11];
	wire [SIZE_OP-1:0] SH = out_instruccion[10:6];
	wire [SIZE_FUNC-1:0] inst_funcion = out_instruccion[5:0];
	wire [SIZE_HALF_INST-1:0] inst_inmediata = out_instruccion[15:0];
	wire [SIZE_FUNC-1:0] inst_funcion_ex;
	
	wire [31:0] jump_address;
	assign jump_address = {ID_addr_instruccion_to_EX[31:28], out_instruccion[25:0], 2'b00};

	wire [SIZE_DATA-1:0] DRead1;
	wire [SIZE_DATA-1:0] DRead2;
	
	wire [SIZE_ADDR_BR-1:0] AWR;
	wire [SIZE_DATA-1:0] Data_Reg;
	wire [SIZE_DATA-1:0] Data_reg_to_mux = Data_Reg;
	wire [SIZE_ADDR_BR-1:0] mem_wb_registerRd;

	Registros BR(
		.ARead1(AR1),
		.ARead2(AR2),
		.AWR(mem_wb_registerRd),
		.DataIn(Data_Reg),
		.WE(writeEn),
		.DRead1(DRead1),
		.DRead2(DRead2)
	);
	
	wire [SIZE_DATA-1:0] A;
	wire [SIZE_DATA-1:0] B;
	wire [SIZE_ADDR_BR-1:0] AdrrDest1;
	wire [SIZE_ADDR_BR-1:0] AdrrDest2;
	wire [ADD_INST_SIZE-1:0] EX_addr_instr_branch;
	wire alusrc_out, sel_regDes;
	wire [SIZE_ALU_OP-1:0] opeAlu;
	wire [S_WB-1:0] wb_ex_mem;
	wire [S_M-1:0] m_ex_mem;
	wire [ADD_SIZE-1:0] offset_to_desp;
	wire [SIZE_DATA-1:0] dato_extendido;
	wire [SIZE_ADDR_BR-1:0] RS;
	wire [SIZE_ADDR_BR-1:0] RT;
	
	wire [SIZE_ADDR_BR-1:0] ex_mem_registerRd;
	wire [SIZE_ADDR_BR-1:0] addr_reg_mem_wb;
	
	assign ex_mem_registerRd = addr_reg_mem_wb;
	
	signed_extention extension(
		.half_word(inst_inmediata),
		.word(dato_extendido),
		.is_unsigned(is_unsigned)
	);

	ID_EX ID_EX(
		.WB({RegWrite, Mem_to_Reg}),
		.M({branch, MemRead, MemWrite}),
		.EX({ALUSrc, ALUOp, RegDest}),
		.clk(clk),
		.data_in(DRead1),
		.data_in2(DRead2),
		.data_in3(ID_addr_instruccion_to_EX),
		.data_extend_in(dato_extendido),
		.if_id_Rs(IF_ID_RS),
		.if_id_Rt(IF_ID_RT),
		.adrWrite1(AR2),
		.adrWrite2(AW),
		.funcion_in(inst_funcion),
		.WB_out(wb_ex_mem),
		.M_out(m_ex_mem),
		.EX_out({alusrc_out, opeAlu, sel_regDes}),
		.data_out(A),
		.data_out2(B),
		.data_out3(EX_addr_instr_branch),
		.data_out_jm(offset_to_desp),
		.funcion(inst_funcion_ex),
		.AWrite1(AdrrDest1),
		.AWrite2(AdrrDest2),
		.Rs(RS),
		.Rt(RT),
		.is_byte_in(is_byte),
		.is_byte_out(is_byte_ex_mem)
	);
	
	
	assign AWR = mem_wb_registerRd;
	wire [S_WB-1:0] WB_mem_wb;
	
	wire ex_mem_RegWrite = WB_mem_wb[1];
	wire mem_wb_RegWrite = writeEn;

	wire [1:0] ForwardA, ForwardB;
	
	wire [SIZE_DATA-1:0] addr_to_memory;
	wire [SIZE_DATA-1:0] dato_to_mux_from_ex_mem = addr_to_memory;
	
	Forward encaminador(
		.in_RS(RS),
		.in_RT(RT),
		.in_ex_mem_regRd(ex_mem_registerRd),
		.in_mem_wb_regRd(mem_wb_registerRd),
		.EX_MEM_RegWrite(ex_mem_RegWrite),
		.MEM_WB_RegWrite(mem_wb_RegWrite),
		.ForwardA(ForwardA),
		.ForwardB(ForwardB)
	);
	
	wire [ADD_INST_SIZE-1:0] instruccion_branch_to_ex_mem;
	wire [ADD_INST_SIZE-1:0] offset_to_adder;
	
	desplazar desplazador(
		.dato(offset_to_desp),
		.datoOut(offset_to_adder)
	);
	
	sumador#(.SIZE(ADD_INST_SIZE)) sumador_despl(
		.A(EX_addr_instr_branch),
		.B(offset_to_adder),
		.res(instruccion_branch_to_ex_mem)
	);
	
	wire [S_OP_ALU-1:0] selector;
	
	ALUcontrol ALUcontrol(
		.instruccion(inst_funcion_ex),
		.AluOP(opeAlu),
		.outInst(selector)
	);
	
	wire [SIZE_DATA-1:0] operando_B; 
	wire [SIZE_DATA-1:0] resultadoALU;
	wire flag_zero_to_alu, flag_zero_to_branch;
	wire [SIZE_DATA-1:0] operando_A;
	wire [SIZE_DATA-1:0] dato_B_to_ALUsrc;
	
	MUX3_1 datoA(
		.A(A),
		.B(Data_reg_to_mux),
		.C(dato_to_mux_from_ex_mem),
		.Forward(ForwardA),
		.dato(operando_A)
	);
	
	MUX3_1 datoB(
		.A(B),
		.B(Data_reg_to_mux),
		.C(dato_to_mux_from_ex_mem),
		.Forward(ForwardB),
		.dato(dato_B_to_ALUsrc)
	);
	
	MUX #(.SIZE(SIZE_DATA)) mux_in_ALU(
		.dato(offset_to_desp),
		.dato2(dato_B_to_ALUsrc),
		.sel(alusrc_out),
		.datoOut(operando_B)	
	);
	
	ALU ALU(
		.a(operando_A),
		.b(operando_B),
		.operador(selector),
		.zero(flag_zero_to_alu),
		.resultado(resultadoALU)
	);
	
	wire [SIZE_ADDR_BR-1:0] ex_mem_addrDest;
	
	MUX #(.SIZE(5)) mux_regDest(
		.dato(AdrrDest2),
		.dato2(AdrrDest1),
		.sel(sel_regDes),
		.datoOut(ex_mem_addrDest)
	);

	wire ex_mem_branch;
	
	wire memoryWrite;
	wire memoryRead;
	wire [SIZE_DATA-1:0] dato_escribir;
	wire [ADD_INST_SIZE-1:0] add_instruccion_to_mux;

	EX_MEM EX_MEM(
		.clk(clk),
		.WB(wb_ex_mem),
		.M(m_ex_mem),
		.zero_in(flag_zero_to_alu),
		.data_in(instruccion_branch_to_ex_mem),
		.data_in2(resultadoALU),
		.AWriteMem_in(B),
		.AWriteReg_in(ex_mem_addrDest),
		.WB_out(WB_mem_wb),
		.M_out({ex_mem_branch, memoryRead, memoryWrite}),
		.zero_out(flag_zero_to_branch),
		.data_out(add_instruccion_to_mux),
		.data_out2(addr_to_memory),
		.AWriteMem(dato_escribir),
		.AWriteReg(addr_reg_mem_wb),
		.is_byte_in(is_byte_ex_mem),
		.is_byte_out(is_byte_mem)
	);
	
	wire [SIZE_DATA-1:0] datoLeido;
	

wire branchToPC;
assign branchToPC = (ex_mem_branch & flag_zero_to_branch) === 1'b1 ? 1'b1 : 1'b0;
	
	wire [31:0] branch_or_pc4;
	MUX #(.SIZE(32)) mux_branch(
		.dato(add_instruccion_to_mux),
		.dato2(addr_instruccion_in),
		.sel(branchToPC),
		.datoOut(branch_or_pc4)
	);

	MUX #(.SIZE(32)) mux_jump(
		.dato(jump_address),
		.dato2(branch_or_pc4),
		.sel(Jump),
		.datoOut(addr_instruccion_to_mux)
	);
	
	memoriaDatos memoriaDatos(
		.address(addr_to_memory),
		.dato(dato_escribir),
		.MemWrite(memoryWrite),
		.MemRead(memoryRead),
		.datoLeido(datoLeido),
		.is_byte(is_byte_mem)
	);
	
	wire [SIZE_DATA-1:0] Dato_leido1, Dato_leido2;
	wire MemToReg;
	
	MEM_WB MEM_WB(
		.clk(clk),
		.WB(WB_mem_wb),
		.DatoLeido(datoLeido),
		.direccion(addr_to_memory),
		.direccionRegistro(addr_reg_mem_wb),
		.WB_out({writeEn, MemToReg}),
		.datoLeido_out(Dato_leido1),
		.direccion_out(Dato_leido2),
		.direccionRegistro_out(mem_wb_registerRd)
	);
	
	MUX mux_MemoryToReg(
		.dato(Dato_leido1),
		.dato2(Dato_leido2),
		.sel(MemToReg),
		.datoOut(Data_Reg)
	);

endmodule