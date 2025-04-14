import ida_idaapi
import ida_hexrays
import ida_kernwin
import ida_funcs
import idaapi
from binascii import unhexlify

log_string_data = []

def hex_to_signed_int32(hex_str):
    val = int(hex_str, 16)
    if val >= 0x80000000:
        val -= 0x100000000
    return val

def decompile_all_functions():
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler 未初始化或不可用。")
        return

    func_count = 0
    for func in range(ida_funcs.get_func_qty()):
        func_ea = ida_funcs.getn_func(func).start_ea
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc is None:
                # print(f"[x] 无法反编译函数: {hex(func_ea)}")
                continue
            # hook.func_printed(cfunc)
            idaapi.open_pseudocode(func_ea, 0)
            func_count += 1
        except ida_hexrays.DecompilationFailure:
            continue
            #print(f"[!] 反编译失败: {hex(func_ea)}")
        # print(f"\n完成，成功反编译了 {func_count} 个函数。")

class FuncStringItem:
    def __init__(self, ea, string):
        self.ea = ea
        self.string = string

class FuncStringViewer(ida_kernwin.Choose):
    def __init__(self,):
        super().__init__(
            "函数字符串列表",
            [ ["函数地址", 20 | ida_kernwin.Choose.CHCOL_HEX], ["字符串内容", 80] ],
            flags=ida_kernwin.Choose.CH_MULTI
        )
        # self.items = [FuncStringItem(ea, s) for ea, s in data_list]
        self.items = []

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        item = self.items[n]
        return [f"{item.ea:08X}", item.string]

    def OnSelectLine(self, n):
        if isinstance(n, list):
            for idx in n:
                ida_kernwin.jumpto(self.items[idx].ea)
        else:
            ida_kernwin.jumpto(self.items[n].ea)
        return 1
    
    def feed(self, data):
        """添加数据到视图中
        data: 可以是单个元组 (ea, string) 或者包含多个元组的列表
        """
        if isinstance(data, tuple):
            self.items.append(FuncStringItem(data[0], data[1]))
        else:
            for ea, s in data:
                self.items.append(FuncStringItem(ea, s))
        self.Refresh()
        return


class FSWriteHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        print("FSWrite Microcode Analysis Hook initialized")
        self.debug_mode = True

    def _debug_print(self, *args):
        """Print debug messages if debug mode is on"""
        if self.debug_mode:
            print("[FSWriteMicrocodeHook]", *args)

    def _build_helper_strncpy(self, minsn, arg):
        # Build the strncpy helper function call
        new_call = ida_hexrays.minsn_t(minsn.ea)
        new_call.opcode = ida_hexrays.m_call

        new_call.l = ida_hexrays.mop_t()
        new_call.l.make_helper("__my_strcpy")

        new_call.r = ida_hexrays.mop_t()
        new_call.r.zero()

        new_call.d = ida_hexrays.mop_t()
        new_call.d.size = 0
        ci = ida_hexrays.mcallinfo_t()
        new_call.d._make_callinfo(ci)

        # Set up the call info
        ci.cc = idaapi.CM_CC_SPECIAL
        ci.return_type = idaapi.tinfo_t(idaapi.BT_VOID)
        ci.return_argloc.set_reg1(0)
        ci.solid_args = 0

        # Create the argument for the strncpy call
        arg1 = ida_hexrays.mcallarg_t()
        arg1._make_strlit(arg)
        arg1_char_t = idaapi.tinfo_t(idaapi.BTMT_CHAR | idaapi.BT_INT8)

        arg1_tinfo = idaapi.tinfo_t()
        arg1_tinfo.create_ptr(arg1_char_t)
        arg1.type = arg1_tinfo
        arg1.size = arg1_tinfo.get_size()

        # Add the argument to the call info
        ci.args.push_back(arg1)

        return new_call

    def _match_fswrite(self, mba):
        dirty = False
        for i in range(mba.qty):
            # self._debug_print("{}:".format(i))
            blk = mba.get_mblock(i)
            minsn = blk.head
            global last_writfs_minsn
            global last_blk
            global write_fs_value
            last_writfs_minsn = None
            write_fs_value = []
            while minsn:
                # self._debug_print(minsn.opcode)
                if minsn.opcode == ida_hexrays.m_call:
                    if minsn.l.t == ida_hexrays.mop_h and minsn.l.helper:
                        helper_name = minsn.l.helper
                        if helper_name.startswith("__writefs"):
                            self._debug_print(f"Found __writefs call at {hex(minsn.ea)}")
                            last_writfs_minsn = minsn
                            last_blk = blk
                            # cheat way
                            dirty = True
                            if minsn.d.t == ida_hexrays.mop_f:
                                callargs = minsn.d.f.args
                                if callargs.size() == 2:
                                    if callargs[1].t == ida_hexrays.mop_n and callargs[0].t == ida_hexrays.mop_n:
                                        dst_val = callargs[0].nnn.value
                                        data_val = callargs[1].nnn.value
                                        write_fs_value.append((hex(dst_val), hex(data_val)))
                                    elif callargs[0].t == ida_hexrays.mop_d and callargs[1].t == ida_hexrays.mop_n:
                                        dst_val = callargs[0].value(is_signed=True)
                                        data_val = callargs[1].nnn.value
                                        write_fs_value.append((hex(dst_val), hex(data_val)))

                            blk.make_nop(minsn)
                            blk.mark_lists_dirty()

                minsn = minsn.next
            if last_writfs_minsn:
                strcpy_src_str = b''
                write_fs_value = sorted(write_fs_value, key=lambda x: hex_to_signed_int32(x[0]))
                self._debug_print(f'write_fs_value list: {write_fs_value}')
                for _ in write_fs_value:
                    s = _[1]
                    if len(s[2:]) % 2 == 0:
                        strcpy_src_str += unhexlify(s[2:])[::-1]
                    else:
                        strcpy_src_str += unhexlify('0' + s[2:])[::-1]
                if b'\n' in strcpy_src_str:
                    strcpy_src_str = strcpy_src_str.replace(b'\n', b'\\n')

                
                self._debug_print(f"strcpy_src_str: {strcpy_src_str.decode('latin')}")
                self._debug_print(f"last_writfs_minsn: {hex(last_writfs_minsn.ea)}")
                new_call = self._build_helper_strncpy(last_writfs_minsn, strcpy_src_str.decode('latin'))
                last_blk.insert_into_block(new_call, last_writfs_minsn)
                self._debug_print([last_writfs_minsn.ea, strcpy_src_str.decode('latin')])
                viewer.feed((last_writfs_minsn.ea, strcpy_src_str.decode('latin')))
        return dirty

    def glbopt(self, mba):
        """Called before after??? the glbopt phase"""
        self._debug_print("glbopt phase")
        dirty = self._match_fswrite(mba)

        return 0 if not dirty else idaapi.MERR_LOOP


class FSMicrocodePlugin(ida_idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "WriteFS Hook"
    wanted_hotkey = ""
    help = ""

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def term(self):
        if hasattr(self, 'hook'):
            self.hook.unhook()
            print("String Pattern Microcode Analyzer uninstalled")

    def run(self, arg):
        if ida_hexrays.init_hexrays_plugin():
            self.hook = FSWriteHook()
            try:
                self.hook.hook()
                decompile_all_functions() 
                viewer.Show()
     

            except Exception as e:
                print(f"Error while hooking: {e}")
        else:
            print("Hex-rays decompiler is not available")
            return ida_idaapi.PLUGIN_SKIP

def PLUGIN_ENTRY():
    global viewer
    viewer = FuncStringViewer()
    return FSMicrocodePlugin()
