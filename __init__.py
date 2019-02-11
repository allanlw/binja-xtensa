from binascii import hexlify
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken, IntrinsicInfo
from binaryninja.enums import (Endianness, ImplicitRegisterExtend, BranchType,
        InstructionTextTokenType, LowLevelILFlagCondition, FlagRole)
from binaryninja.enums import LowLevelILOperation, LowLevelILFlagCondition, InstructionTextTokenType
from binaryninja.lowlevelil import LowLevelILLabel
from binaryninja.functionrecognizer import FunctionRecognizer
from binaryninja.callingconvention import CallingConvention
from binascii import hexlify, unhexlify
import binaryninja.log as log
import r2pipe
import threading
import traceback
from collections import namedtuple


# Helper function to make tokens easier to make
def makeToken(tokenType, text, data=None):
    tokenType = {
            'inst':InstructionTextTokenType.InstructionToken,
            'text':InstructionTextTokenType.TextToken,
            'addr':InstructionTextTokenType.PossibleAddressToken,
		'int': InstructionTextTokenType.IntegerToken,
            'sep':InstructionTextTokenType.OperandSeparatorToken,
		"reg": InstructionTextTokenType.RegisterToken,
    }[tokenType]

    if data is None:
        return InstructionTextToken(tokenType, text)
    return InstructionTextToken(tokenType, text, data)

# This class duck types as an LowLevelILFunction
# but only implements methods necessary to
# perform "goto"
#
# It's used to emulate an ESIL branch to see
# if it only generates a simple 'goto' in which
# case it is inlined instead of creating a separate
# label and block
class ThreaderILDuck(object):
	def __init__(self):
		self.target = None
	def append(self, instruction):
		pass
	def goto(self, label):
		self.target = label
	def __getitem__(self, key):
		instructionduck = type('', (), {
			"operation": LowLevelILOperation.LLIL_CONST,
			"operands": [key]
		})()
		return instructionduck
	def const(self, size, n):
		return n
	def get_label_for_address(self, arch, target):
		return target

# LittleEndian Xtensa
class XtensaLE(Architecture):
        name = "Xtensa LE"
        endianness = Endianness.LittleEndian
        address_size = 4
        default_int_size = 4
        instr_alignment = 1
        max_instr_length = 3

	# Include extra useless garbage in the LLIL
	# and also dump ESIL in the instruction
	VERBOSE_IL = False

	regs = {
		"pc": RegisterInfo("pc", 4),
		"sar": RegisterInfo("sar", 1), # actually 6 bits but whatever
		"lbegin": RegisterInfo("lbegin", 4),
		"lend": RegisterInfo("lend", 4),
		"lcount": RegisterInfo("lcount", 4),
		# ours actually just has the full number, not the log_2 of it
		"PS.CALLINC": RegisterInfo("PS.CALLINC", 1),
	}
	stack_pointer = 'a1' # Standard ABI
	# Note: not using a reg_stack because this is intended for x87/FPU
	# it's not intended for windowed registers
	for i in range(16):
		n = "a{0}".format(i)
		regs[n] = RegisterInfo(n, 4)

	intrinsics = {
		"memw": IntrinsicInfo([], []),
		"entry": IntrinsicInfo([], []),
	}

	_branch_instrs = ["bbci", "bbsi", "bgeu", "bltu", "bany", "bnone", "ball", "bnall", "bbc", "bbs"]
	for operand in ["z", "i", "ui", ""]:
		for cmp in ["eq", "ne", "ge", "lt"]:
			_branch_instrs.append("b"+cmp+operand)

	_esil_to_llil = {
		"-": "sub",
		"+": "add",
		"&": "and_expr",
		"|": "or_expr",
		"^": "xor_expr",
		">>": "logical_shift_right", #??
		"<<": "shift_left",
		"==": "compare_equal",
		">=": "compare_unsigned_greater_equal",
		"<=": "compare_unsigned_less_equal",
		">": "compare_unsigned_greater_than",
		"<": "compare_unsigned_less_than",
	}

	def __init__(self):
		super(XtensaLE, self).__init__()
		self.r2 = self._init_r2()
		self.cache = {}
		self._lock = threading.Lock()
		self._looplock = threading.Lock()
		self.loops = {}
	def _init_r2(self):
		r = r2pipe.open('/dev/null')
		r.cmd("e asm.arch=xtensa")
		return r
	def _r2_cache(self, cmd):
		with self._lock:
			if cmd in self.cache:
				return self.cache[cmd]
			res = self.r2.cmd(cmd)
			self.cache[cmd] = res
			return res
	def _inst_length(self, name):
		return 2 if name.endswith(".n") else 3
	def _get_asm(self, data, addr):
		asm = self._r2_cache("s {0}; pad {1}".format(addr, hexlify(data)))
		firstline = asm.strip().split("\n")[0].encode("ascii")
		if " " not in firstline:
			return firstline, []
		inst, args = firstline.split(" ", 1)
		inst = inst.lower()
		args = args.split(", ")
		return inst, args
	def _get_esil(self, data, addr):
		return self._r2_cache("s {0}; pade {1}".format(addr, hexlify(data))).strip().encode("ascii")
	def _get_reil(self, esil):
		return self._r2_cache("aetr '" + esil + "'")
	def get_instruction_info(self, data, addr):
		inst,args = self._get_asm(data, addr)
		if inst == "ill":
			return None
		res = InstructionInfo()
		res.length = self._inst_length(inst)

		if inst in ("jx"):
			if args[0] in self.regs:
				res.add_branch(BranchType.IndirectBranch)
			else:
				res.add_branch(BranchType.UnconditionalBranch, int(args[0], 16))
		elif inst in ("callx0", "callx4", "callx8", "callx12"):
			res.add_branch(BranchType.CallDestination)
		elif inst in ("ret", "retw", "ret.n", "retw.n"):
			res.add_branch(BranchType.FunctionReturn)
		elif inst == "j":
			res.add_branch(BranchType.UnconditionalBranch, int(args[0], 16))
		elif inst in ("call0", "call4", "call8", "call12"):
			res.add_branch(BranchType.CallDestination, int(args[0], 16))
		elif inst in ("loopgtz", "loopnez"):
			res.add_branch(BranchType.FalseBranch, int(args[1], 16))
			res.add_branch(BranchType.TrueBranch, addr + res.length)
		elif inst in self._branch_instrs or (inst.endswith(".n") and inst[:-2] in self._branch_instrs):
			res.add_branch(BranchType.TrueBranch, int(args[-1], 16))
			res.add_branch(BranchType.FalseBranch, addr + res.length)
		return res
	def get_instruction_text(self, data, addr):
		inst,args = self._get_asm(data, addr)
		if inst == "ill":
			return None
		tokens = []
		tokens.append(makeToken("inst", inst))
		tokens.append(makeToken("sep", " "))
		for i, arg in enumerate(args):
			if i != 0:
				tokens.append(makeToken("sep", ", "))
			if arg.startswith("0x"):
				tokens.append(makeToken("addr", arg))
			elif arg.isdigit():
				tokens.append(makeToken("int", arg))
			else:
				tokens.append(makeToken("reg", arg))

		if self.VERBOSE_IL:
			esil = self._get_esil(data, addr)
			tokens.append(makeToken("sep", "    "))
			tokens.append(makeToken("text", "esil='"+esil+"'"))

		return tokens, self._inst_length(inst)
	def force_label(self, il, a):
		t = il.get_label_for_address(self, a)
		if t is None:
			t = il.add_label_for_address(self, a)
			if t is None:
				return self.force_label(il, a)
		return t

	def goto_or_jmp(self, il, a):
		t = self.force_label(il, a)
		if t is None:
			il.append(il.jump(il.const(4, a)))
		else:
			il.append(il.goto(t))

	def get_instruction_low_level_il(self, data, addr, il):
		locals = threading.local()
		inst,args = self._get_asm(data, addr)
		if inst == "ill":
			return None
		l = self._inst_length(inst)

		if inst in ("jx"):
			if args[0] in self.regs:
				il.append(il.jump(il.reg(4, args[0])))
			else:
				self.goto_or_jmp(il, int(args[0], 16))
			return l
		elif inst.startswith("call"):
			spilled_regs = int(inst[5 if inst.startswith("callx") else 4:])
			# Spill onto stack
			a = lambda a: "a{0}".format(a)
			r = lambda r: il.reg(4, "a{0}".format(r))
#			if spilled_regs != 0:
#				for i in range(spilled_regs):
#					il.append(il.push(4, r(i)))
#				for i in range(spilled_regs, 16):
#					il.append(il.set_reg(4, a(i-spilled_regs), r(i)))
			if spilled_regs != 0 and self.VERBOSE_IL:
				il.append(il.set_reg(1, "PS.CALLINC", il.const(1, spilled_regs)))
			# return address
#			il.append(il.set_reg(4, a(spilled_regs), il.const(4, addr + l)))
			target = il.reg(4, args[0]) if inst.startswith("callx") else il.const(4, int(args[0], 16))
			il.append(il.call(target))
			# unspill from stack
#			if spilled_regs != 0:
#				for i in range(15, spilled_regs-1, -1):
#					il.append(il.set_reg(4, a(i), r(i-spilled_regs)))
#				for i in range(spilled_regs-1, -1, -1):
#					il.append(il.set_reg(4, a(i), il.pop(4)))
			return l
		elif inst in ("ret", "retw", "ret.n", "retw.n"):
			il.append(il.ret(il.reg(4, "a0")))
			return l
		elif inst == "j":
			il.append(il.jump(il.const(4, int(args[0], 16))))
			return l
		elif inst in ("loopgtz", "loopnez", "loop"):
			lbegin = addr + l
			lend = int(args[1], 16)
			r = il.reg(4, args[0])
			lcount = il.sub(4, r, il.const(4,1))
			# lend must come before lbegin for loop detection to work lower down
			if self.VERBOSE_IL:
				il.append(il.set_reg(4, "lend", il.const(4, lend)))
				il.append(il.set_reg(4, "lbegin", il.const(4, lbegin)))
				il.append(il.set_reg(4, "lcount", lcount))
			if inst in ("loopgtz", "loopnez"):
				t = self.force_label(il, lbegin)
				f = self.force_label(il, lend)
				set_t = False
				set_f = False
				if t is None:
					set_t = True
					t = LowLevelILLabel()
				if f is None:
					set_f = True
					f = LowLevelILLabel()
				if inst == "loopnez":
					cond = il.compare_unsigned_greater_equal(4, r, il.const(4, 0))
				else:
					cond = il.compare_signed_greater_equal(4, r, il.const(4, 0))
				il.append(il.if_expr(cond, t, f))
				if set_f:
					il.mark_label(f)
					self.goto_or_jmp(il, lend)
				if set_t:
					il.mark_label(t)
					# fallthrough

			with self._looplock:
				self.loops[lend] = lbegin
			return l
		elif inst == "entry":
			# Entry doesn't *do* anything, basically
			il.append(il.intrinsic([], "entry", []))
			return l
		elif inst == "memw":
			il.append(il.intrinsic([], "memw", []))
			return l
		esil = self._get_esil(data[0:l], addr)
		if esil == "":
			il.append(il.unimplemented())
			return l
		parts = esil.split(",")

		# For basic instructions, interpret the ESIL
		self.esil_to_llil(inst, parts, il, addr, l)

		# Scan the function for loop instructions pointing to here
		lbegin = None
		with self._looplock:
			n = addr + l
			if n in self.loops:
				lbegin = self.loops[n]
		if lbegin is not None:
			cond = il.compare_unsigned_greater_than(4, il.reg(4, "lcount"), il.const(4, 0))
			f = self.force_label(il, n)
			t = self.force_label(il, lbegin) #il.get_label_for_address(self, lbegin)
			set_f = False
			set_t = False
			if f is None:
				set_f = True
				f = LowLevelILLabel()
			if t is None:
				set_t = True
				t = LowLevelILLabel()

			il.append(il.if_expr(cond, t, f))
			if set_t:
				il.mark_label(t)
				self.goto_or_jmp(il, lbegin)
			if set_f:
				il.mark_label(f)
				# fallthrough
		return l

	# Implement a basic stack machine to translate ESIL to LLIL
	def esil_to_llil(self, inst, parts, il, addr, l):
		stack = []
		label_stack = []
		skip_to_close = False
		# pop for reading - interprets the PC register as
		# the value of the next instruction
		def popr():
			r = stack.pop()
			if r == "pc":
				return il.const(4, addr + l)
			return r
		for i, token in enumerate(parts):
			# No idea why I need this
			if token == "" and i == len(parts)-1:
				break
			if skip_to_close and token != "}": continue
			if token == "$$":
				stack.append(il.const(4, addr))
				continue
			if token == "pc":
				stack.append("pc")
				continue
			if token in self.regs:
				stack.append(il.reg(4, token))
				continue
			if token in self._esil_to_llil:
				dst = popr()
				src = popr()
				stack.append(getattr(il, self._esil_to_llil[token])(4, dst, src))
				continue
			if token == "$z" or token == "!":
				stack.append(il.compare_equal(4, stack[-1], il.const(4, 0)))
				continue
			if token == "DUP":
				stack.append(stack[-1])
				continue
			if token == "=":
				dst = stack.pop()
				src = popr()
				if dst == "pc":
					srci = il[src]
					if srci.operation == LowLevelILOperation.LLIL_CONST:
						self.goto_or_jmp(il, srci.operands[0])
						continue
					il.append(il.jump(src))
					continue
				dst = il[dst]
				if dst.operation != LowLevelILOperation.LLIL_REG:
					raise ValueError("unimplemented il store to {0!r}".format(dst))
				il.append(il.set_reg(4, dst.operands[0].name, src))
				continue
			if token == "+=":
				dste = stack.pop()
				src = popr()
				if dste == "pc":
					srci = il[src]
					# Note in ESIL this is w.r.t. the *next* address
					# For narrow branch instructions, it calculates the pc relative
					# wrong in the ESIL and uses 3 bytes anyway
					# also, srci.operands[0] is 8 bytes *signed* but ESIL
					# doesn't seem to reflect this?
					# Note: except beqz, bnez, bgez, bltz which have 12 bytes *signed*
					# and beqz.n and bnez.n which are 4 bytes unsigned
					if srci.operation == LowLevelILOperation.LLIL_CONST:
						offset = srci.operands[0]
						if inst in ("beqz", "bnez", "bgez", "bltz"):
							if offset > (1 << 11) - 1:
								offset = ((1<<12)-offset) * -1
						elif inst in ("beqz.n", "bnez.n"): pass
						elif offset > 127:
							offset = (256-offset) * -1
						self.goto_or_jmp(il, offset + addr + 3)
					else:
						il.append(il.jump(il.add(4, il.const(4, addr + 3), src)))
					continue
				dst = il[dste]
				if dst.operation != LowLevelILOperation.LLIL_REG:
					raise ValueError("unimplemented il store to {0!r}".format(dst))
				il.append(il.set_reg(4, dst.operands[0].name, il.add(4, dste, src)))
				continue
			if token.startswith("=["):
				sz = int(token[2:-1])
				dst = popr()
				src = popr()
				il.append(il.store(sz, dst, src))
				continue
			if token.startswith("["):
				sz = int(token[1:-1])
				if sz == 1 or sz == 2:
					stack.append(il.zero_extend(4, il.load(sz, popr())))
				elif sz == 4:
					stack.append(il.load(4, popr()))
				else:
					raise ValueError("Invalid load size {0}".format(sz))
				continue
			# Base 16 constants
			try:
				i = int(token, 16)
			except ValueError:
				pass
			else:
				stack.append(il.const(4, i))
				continue
			# Base 10 constants
			try:
				i = int(token)
			except ValueError:
				pass
			else:
				stack.append(il.const(4, i))
				continue

			# Hack to support branch instructions
			if token == "?{":
				t = None
				set_t = False
				end = parts.index("}", i+1)

				f = None
				# Don't create useless labels if this is at the end
				# of the instruction (e.g. a branch)
				if end == len(parts)-1:
					f = self.force_label(il, addr+l)
				if f is None:
					f = LowLevelILLabel()
					label_stack.append(f)

				inner = parts[i+1:end]

				fakeil = ThreaderILDuck()
				try:
					self.esil_to_llil(inst, inner, fakeil, addr, l)
				except AttributeError as e:
					pass
				except IndexError as e: # Tried to access the stack outside! Bad!
					pass
				except Exception as e:
					log.log_error("{0} {1}".format(e, inner))
					raise e
				else:
					if fakeil.target is not None:
						t = self.force_label(il, fakeil.target)
#						log.log_info("Prediction successful at {0:X}, {1}, {2:X} {3} {4}".format(addr, inner, fakeil.target, t, parts))
#					else:
#						log.log_warn("Prediction succesful but no target {0} {1}".format(inner, parts))

				if t is None:
					set_t = True
					t = LowLevelILLabel()

				il.append(il.if_expr(stack.pop(), t, f))
				if set_t:
					il.mark_label(t)
				elif len(label_stack) == 0:
					break
				else:
					skip_to_close = True
				continue

			if token == "}":
				if len(label_stack) == 0: break
				il.mark_label(label_stack.pop())
				skip_to_close = False
				continue

			raise ValueError("Unimplemented esil {0} in {1} for {2}".format(token, esil, inst))



class XtensaFunctionRecognizer(FunctionRecognizer):
	def recognize_low_level_il(self, data, func, il):
		first_inst = func.instructions.next()
		res = first_inst[0][0].text == "entry"
		if res:
			func.name = "XTFUNC_{0:X}".format(first_inst[1])
		# look for 0x36 (Entry instruction) immediately following the bottom of this function
		try:
			end = max(b.end for b in func.basic_blocks)
			for i in range(4):
				ei = end+i
				b = data.read(ei, 1)
				if b == '\x36':
					if data.get_function_at(ei) is not None: break
					data.add_function(ei)
					break
				if b != '\x00': break
		except Exception as e:
			log.log_error(traceback.format_exc())
		return res

# Note, these are the registers as seen by the callee
class XtensaWindowedCallingConvention(CallingConvention):
	int_arg_regs = ["a2", "a3", "a4", "a5", "a6", "a7", "PS.CALLINC"]
	int_return_reg = "a2"
	stack_adjusted_on_return = False


XtensaLE.register()
arch = Architecture["Xtensa LE"]
#arch.register_calling_convention(XtensaWindowedCallingConvention(arch, 'windowed'))
BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian, arch)
XtensaFunctionRecognizer.register_arch(arch)
