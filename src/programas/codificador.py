import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox


class MIPSAssembler:
    def __init__(self, root):
        self.root = root
        self.root.title("MIPS Assembler/Disassembler - NucleoTop")
        self.root.geometry("1200x700")
        self.root.configure(bg="#f0f4f8")

        # Diccionario de instrucciones
        # Ajustado para tu arquitectura NucleoTop según el módulo Control
        self.instructions = {
            # R-type (opcode = 000000)
            'add': {'type': 'R', 'opcode': '000000', 'funct': '100000', 'alu_op': '0010'}, # 0010 en ALUcontrol
            'sub': {'type': 'R', 'opcode': '000000', 'funct': '100010', 'alu_op': '0110'}, # 0110 en ALUcontrol
            'and': {'type': 'R', 'opcode': '000000', 'funct': '100100', 'alu_op': '0000'}, # 0000 en ALUcontrol
            'or':  {'type': 'R', 'opcode': '000000', 'funct': '100101', 'alu_op': '0001'}, # 0001 en ALUcontrol
            'slt': {'type': 'R', 'opcode': '000000', 'funct': '101010', 'alu_op': '0111'}, # 0111 en ALUcontrol
            # NOP: add $zero, $zero, $zero
            'nop': {'type': 'R', 'opcode': '000000', 'funct': '100000', 'alu_op': '0010'}, # Mismo que add

            # I-type
            'addi': {'type': 'I', 'opcode': '001000'},
            'lw':   {'type': 'I', 'opcode': '100011'},
            'sw':   {'type': 'I', 'opcode': '101011'},
            'lb':   {'type': 'I', 'opcode': '100000'}, # Load Byte
            'sb':   {'type': 'I', 'opcode': '101000'}, # Store Byte
            'beq':  {'type': 'I', 'opcode': '000100'},
            'bne':  {'type': 'I', 'opcode': '000101'}, # Añadido para NucleoTop

            # J-type
            'j': {'type': 'J', 'opcode': '000010'}
        }

        # Diccionario de registros
        # Ajustado para coincidir con tu ejemplo ($10, $11, etc.)
        self.registers = {
            '$0': '00000', '$zero': '00000',
            '$1': '00001', '$at': '00001',
            '$2': '00010', '$v0': '00010',
            '$3': '00011', '$v1': '00011',
            '$4': '00100', '$a0': '00100',
            '$5': '00101', '$a1': '00101',
            '$6': '00110', '$a2': '00110',
            '$7': '00111', '$a3': '00111',
            '$8': '01000', '$t0': '01000',
            '$9': '01001', '$t1': '01001',
            '$10': '01010', '$t2': '01010',
            '$11': '01011', '$t3': '01011',
            '$12': '01100', '$t4': '01100',
            '$13': '01101', '$t5': '01101',
            '$14': '01110', '$t6': '01110',
            '$15': '01111', '$t7': '01111',
            '$16': '10000', '$s0': '10000',
            '$17': '10001', '$s1': '10001',
            '$18': '10010', '$s2': '10010',
            '$19': '10011', '$s3': '10011',
            '$20': '10100', '$s4': '10100',
            '$21': '10101', '$s5': '10101',
            '$22': '10110', '$s6': '10110',
            '$23': '10111', '$s7': '10111',
            '$24': '11000', '$t8': '11000',
            '$25': '11001', '$t9': '11001',
            '$26': '11010', '$k0': '11010',
            '$27': '11011', '$k1': '11011',
            '$28': '11100', '$gp': '11100',
            '$29': '11101', '$sp': '11101',
            '$30': '11110', '$fp': '11110',
            '$31': '11111', '$ra': '11111'
        }

        # Diccionario inverso para desensamblado
        self.reg_names = {v: k for k, v in self.registers.items() if k.startswith('$') and len(k) <= 3}

        self.mode = tk.StringVar(value="asm2bin")
        self.create_widgets()

    def create_widgets(self):
        # Frame principal
        main_frame = tk.Frame(self.root, bg="#f0f4f8")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Título
        title_label = tk.Label(main_frame, text="MIPS Assembler/Disassembler - NucleoTop",
                               font=("Helvetica", 24, "bold"), bg="#f0f4f8", fg="#1e3a8a")
        title_label.pack(pady=(0, 10))

        subtitle_label = tk.Label(main_frame,
                                  text="Convierte entre código ensamblador MIPS y código máquina hexadecimal para NucleoTop",
                                  font=("Helvetica", 10), bg="#f0f4f8", fg="#64748b")
        subtitle_label.pack(pady=(0, 20))

        # Frame de modo
        mode_frame = tk.Frame(main_frame, bg="#f0f4f8")
        mode_frame.pack(pady=(0, 15))

        tk.Radiobutton(mode_frame, text="Ensamblador → Binario/Hex",
                      variable=self.mode, value="asm2bin",
                      font=("Helvetica", 11), bg="#f0f4f8",
                      command=self.update_labels).pack(side=tk.LEFT, padx=10)

        tk.Radiobutton(mode_frame, text="Binario/Hex → Ensamblador",
                      variable=self.mode, value="bin2asm",
                      font=("Helvetica", 11), bg="#f0f4f8",
                      command=self.update_labels).pack(side=tk.LEFT, padx=10)

        # Frame de botones
        button_frame = tk.Frame(main_frame, bg="#f0f4f8")
        button_frame.pack(pady=(0, 15))

        tk.Button(button_frame, text="📁 Cargar archivo", command=self.load_file,
                 bg="#3b82f6", fg="white", font=("Helvetica", 10, "bold"),
                 padx=15, pady=8, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)

        tk.Button(button_frame, text="📋 Cargar ejemplo", command=self.load_example,
                 bg="#10b981", fg="white", font=("Helvetica", 10, "bold"),
                 padx=15, pady=8, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)

        tk.Button(button_frame, text="💾 Guardar resultado", command=self.save_file,
                 bg="#8b5cf6", fg="white", font=("Helvetica", 10, "bold"),
                 padx=15, pady=8, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)

        # Frame de contenido (dos columnas)
        content_frame = tk.Frame(main_frame, bg="#f0f4f8")
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Columna izquierda (entrada)
        left_frame = tk.Frame(content_frame, bg="white", relief=tk.RAISED, bd=2)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        self.input_label = tk.Label(left_frame, text="Código Ensamblador",
                                    font=("Helvetica", 12, "bold"), bg="white", fg="#1e293b")
        self.input_label.pack(pady=10)

        self.input_text = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD,
                                                    font=("Courier New", 10),
                                                    bg="#f8fafc", fg="#1e293b")
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Botón convertir
        convert_btn = tk.Button(left_frame, text="⚡ CONVERTIR", command=self.convert,
                               bg="#4f46e5", fg="white", font=("Helvetica", 12, "bold"),
                               padx=30, pady=10, relief=tk.FLAT, cursor="hand2")
        convert_btn.pack(pady=(0, 10))

        # Columna derecha (salida)
        right_frame = tk.Frame(content_frame, bg="white", relief=tk.RAISED, bd=2)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.output_label = tk.Label(right_frame, text="Código Hexadecimal",
                                     font=("Helvetica", 12, "bold"), bg="white", fg="#1e293b")
        self.output_label.pack(pady=10)

        self.output_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD,
                                                     font=("Courier New", 10),
                                                     bg="#f1f5f9", fg="#1e293b",
                                                     state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Frame de errores
        self.error_frame = tk.Frame(main_frame, bg="#fee2e2", relief=tk.RAISED, bd=2)
        self.error_text = scrolledtext.ScrolledText(self.error_frame, wrap=tk.WORD,
                                                    font=("Helvetica", 9),
                                                    bg="#fee2e2", fg="#991b1b",
                                                    height=5, state=tk.DISABLED)
        self.error_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def update_labels(self):
        if self.mode.get() == "asm2bin":
            self.input_label.config(text="Código Ensamblador")
            self.output_label.config(text="Código Hexadecimal")
        else:
            self.input_label.config(text="Código Hexadecimal")
            self.output_label.config(text="Código Ensamblador")

    def to_binary(self, num, bits):
        """Convierte un número a binario con la cantidad de bits especificada"""
        return format(num & ((1 << bits) - 1), f'0{bits}b')

    def to_hex(self, binary):
        """Convierte binario a hexadecimal"""
        return format(int(binary, 2), '08x')

    def parse_immediate(self, imm):
        """Parsea un valor inmediato (decimal o hexadecimal)"""
        if imm.startswith('0x'):
            return int(imm, 16)
        return int(imm, 10)

    def assemble_instruction(self, line, line_num):
        """Ensambla una instrucción MIPS a código máquina"""
        line = line.strip().lower()

        # Ignorar comentarios y líneas vacías
        if not line or line.startswith('#'):
            return None

        # Remover comentarios al final
        line = line.split('#')[0].strip()

        # Remover etiquetas
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) > 1:
                line = parts[1].strip()
            else:
                return None

        if not line:
            return None

        # Manejo especial para NOP
        if line == 'nop':
            # NOP es add $zero, $zero, $zero
            rs = self.registers['$zero']
            rt = self.registers['$zero']
            rd = self.registers['$zero']
            shamt = '00000'
            funct = self.instructions['add']['funct'] # Usar funct de 'add'
            binary = self.instructions['add']['opcode'] + rs + rt + rd + shamt + funct
            hex_code = self.to_hex(binary)
            return {'binary': binary, 'hex': hex_code, 'original': 'nop'}

        # Separar instrucción y operandos
        parts = [p for p in line.replace(',', ' ').replace('(', ' ').replace(')', ' ').split() if p]
        instr = parts[0]

        if instr not in self.instructions:
            raise ValueError(f"Línea {line_num}: Instrucción desconocida '{instr}'")

        info = self.instructions[instr]
        binary = ''

        if info['type'] == 'R':
            # Formato R: op rs rt rd shamt funct
            if len(parts) != 4:
                raise ValueError(f"Línea {line_num}: {instr} requiere 3 registros (rd, rs, rt)")

            rd = self.registers.get(parts[1])
            rs = self.registers.get(parts[2])
            rt = self.registers.get(parts[3])

            if not all([rd, rs, rt]):
                raise ValueError(f"Línea {line_num}: Registro inválido")

            # Para NOP, ya se maneja arriba
            if instr == 'nop':
                 # Este caso no debería llegar aquí si NOP es manejado arriba
                 pass
            else:
                # Usar funct real de la instrucción
                funct = info['funct']
                binary = info['opcode'] + rs + rt + rd + '00000' + funct

        elif info['type'] == 'I':
            if instr in ['lw', 'sw', 'lb', 'sb']:
                # Formato: lw/sw/lb/sb $rt, offset($rs)
                if len(parts) < 3:
                    raise ValueError(f"Línea {line_num}: {instr} requiere formato: $rt, offset($rs)")

                rt = self.registers.get(parts[1])
                # Para lb/sb, parts[2] es el offset, parts[3] es la base
                # Para lw/sw, parts[2] es el offset, parts[3] es la base
                try:
                    offset = self.parse_immediate(parts[2])
                    rs = self.registers.get(parts[3])
                except (IndexError, ValueError):
                    raise ValueError(f"Línea {line_num}: Formato inválido para {instr}, se esperaba $rt, offset($rs)")

                if not all([rt, rs]):
                    raise ValueError(f"Línea {line_num}: Registro inválido")

                binary = info['opcode'] + rs + rt + self.to_binary(offset, 16)

            elif instr in ['beq', 'bne']:
                # Formato: beq/bne $rs, $rt, offset
                if len(parts) != 4:
                    raise ValueError(f"Línea {line_num}: {instr} requiere 2 registros y un offset")

                rs = self.registers.get(parts[1])
                rt = self.registers.get(parts[2])
                offset = self.parse_immediate(parts[3])

                if not all([rs, rt]):
                    raise ValueError(f"Línea {line_num}: Registro inválido")

                binary = info['opcode'] + rs + rt + self.to_binary(offset, 16)

            else:  # addi
                # Formato: addi $rt, $rs, imm
                if len(parts) != 4:
                    raise ValueError(f"Línea {line_num}: addi requiere formato: $rt, $rs, imm")

                rt = self.registers.get(parts[1])
                rs = self.registers.get(parts[2])
                imm = self.parse_immediate(parts[3])

                if not all([rt, rs]):
                    raise ValueError(f"Línea {line_num}: Registro inválido")

                binary = info['opcode'] + rs + rt + self.to_binary(imm, 16)

        elif info['type'] == 'J':
            # Formato J: op address
            if len(parts) != 2:
                raise ValueError(f"Línea {line_num}: j requiere una dirección")

            address = self.parse_immediate(parts[1])
            binary = info['opcode'] + self.to_binary(address, 26)

        if binary: # Solo si se generó un código binario (no para líneas vacías o comentarios)
            hex_code = self.to_hex(binary)
            return {'binary': binary, 'hex': hex_code, 'original': line}
        return None

    def disassemble_instruction(self, hex_code, line_num):
        """Desensambla código máquina a instrucción MIPS"""
        hex_code = hex_code.strip().lower().replace('0x', '')

        if not all(c in '0123456789abcdef' for c in hex_code) or len(hex_code) != 8:
            raise ValueError(f"Línea {line_num}: Formato hexadecimal inválido '{hex_code}'")

        binary = format(int(hex_code, 16), '032b')
        opcode = binary[0:6]

        if opcode == '000000':
            # R-type
            rs = binary[6:11]
            rt = binary[11:16]
            rd = binary[16:21]
            shamt = binary[21:26]
            funct = binary[26:32]

            # Verificar si es NOP: add $zero, $zero, $zero
            if rs == '00000' and rt == '00000' and rd == '00000' and funct == '100000':
                 return 'nop'

            instr_name = None
            for name, info in self.instructions.items():
                if info['type'] == 'R' and info['funct'] == funct:
                    instr_name = name
                    break

            if not instr_name or instr_name == 'nop': # 'nop' ya está manejado
                if not instr_name:
                    raise ValueError(f"Línea {line_num}: Función desconocida {funct}")
                # Si es NOP, ya se retornó arriba
                return 'nop'

            return f"{instr_name} {self.reg_names[rd]}, {self.reg_names[rs]}, {self.reg_names[rt]}"

        elif opcode == '000010':
            # J-type
            address = int(binary[6:32], 2)
            return f"j {address}"

        else:
            # I-type
            rs = binary[6:11]
            rt = binary[11:16]
            imm_raw = binary[16:32]
            imm = int(imm_raw, 2)
            # Interpretar inmediato como sign-extended para desensamblado de offset/imm
            imm_signed = imm if imm < 32768 else imm - 65536 # 2^15

            instr_name = None
            for name, info in self.instructions.items():
                if info['opcode'] == opcode:
                    instr_name = name
                    break

            if not instr_name:
                raise ValueError(f"Línea {line_num}: Opcode desconocido {opcode}")

            if instr_name in ['lw', 'sw', 'lb', 'sb']:
                # Formato: instr $rt, imm($rs)
                return f"{instr_name} {self.reg_names[rt]}, {imm_signed}({self.reg_names[rs]})"
            elif instr_name in ['beq', 'bne']:
                # Formato: instr $rs, $rt, imm
                return f"{instr_name} {self.reg_names[rs]}, {self.reg_names[rt]}, {imm_signed}"
            else:  # addi
                # Formato: addi $rt, $rs, imm
                return f"{instr_name} {self.reg_names[rt]}, {self.reg_names[rs]}, {imm_signed}"

    def convert(self):
        """Convierte el código según el modo seleccionado"""
        input_code = self.input_text.get("1.0", tk.END)
        lines = input_code.strip().split('\n')

        results = []
        errors = []

        try:
            if self.mode.get() == "asm2bin":
                for idx, line in enumerate(lines, 1):
                    try:
                        result = self.assemble_instruction(line, idx)
                        if result:
                            results.append(f"{result['hex']}  # {result['original']}")
                    except Exception as e:
                        errors.append(str(e))
            else:
                for idx, line in enumerate(lines, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        line = line.split('#')[0].strip()
                        try:
                            result = self.disassemble_instruction(line, idx)
                            results.append(result)
                        except Exception as e:
                            errors.append(str(e))

            # Mostrar resultado
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", '\n'.join(results))
            self.output_text.config(state=tk.DISABLED)

            # Mostrar errores si los hay
            if errors:
                self.error_frame.pack(fill=tk.X, pady=(10, 0))
                self.error_text.config(state=tk.NORMAL)
                self.error_text.delete("1.0", tk.END)
                self.error_text.insert("1.0", "⚠️ ERRORES ENCONTRADOS:\n\n" + '\n'.join(errors))
                self.error_text.config(state=tk.DISABLED)
            else:
                self.error_frame.pack_forget()
                # messagebox.showinfo("Éxito", "✓ Conversión completada exitosamente") # Quitado para no molestar tanto

        except Exception as e:
            messagebox.showerror("Error", f"Error en la conversión: {str(e)}")

    def load_file(self):
        """Carga un archivo de texto"""
        filename = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as file:
                    content = file.read()
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo cargar el archivo: {str(e)}")

    def save_file(self):
        """Guarda el resultado en un archivo"""
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Advertencia", "No hay contenido para guardar")
            return

        default_ext = ".hex" if self.mode.get() == "asm2bin" else ".asm"
        filename = filedialog.asksaveasfilename(
            title="Guardar archivo",
            defaultextension=default_ext,
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as file:
                    file.write(content)
                messagebox.showinfo("Éxito", "Archivo guardado correctamente")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el archivo: {str(e)}")

    def load_example(self):
        """Carga un ejemplo de código para NucleoTop"""
        # Ejemplo de búsqueda lineal adaptado a tu formato
        example = """nop
addi $11, $0, 5        # $11 = tamaño del array (N)
addi $15, $0, 0x1000   # $15 = dirección base del array
addi $10, $0, 0x2000   # $10 = dirección donde está el valor a buscar
addi $12, $0, 0        # $12 = índice = 0
addi $13, $0, 0        # $13 = valor buscado (cargado de memoria después)

lw $13, 0($10)         # Cargar valor a buscar en $13
nop
nop
bucle_inicio:
lw $14, 0($15)         # Cargar array[indice] en $14
addi $15, $15, 4       # Incrementar dirección para siguiente carga
nop
sub $16, $14, $13      # $16 = array[indice] - valor_buscado
nop
beq $16, $0, encontrado # Si son iguales, salta a encontrado
nop
addi $12, $12, 1       # Incrementar índice
nop
sub $17, $11, $12      # $17 = N - indice
nop
bne $17, $0, bucle_inicio # Si indice < N, volver al bucle
nop
j fin                  # Si no encontró, salta al final
nop
encontrado:
addi $8, $0, 1         # $8 = 1 (indicador de éxito)
j fin
nop
fin:
addi $8, $0, 0         # $8 = 0 (indicador de fallo si no entró en 'encontrado')"""
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", example)


if __name__ == "__main__":
    root = tk.Tk()
    app = MIPSAssembler(root)
    root.mainloop()
