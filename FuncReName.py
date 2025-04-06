"""
func_rename.py

Created by swing on 11/12/20
"""

FuncReName_USE_AS_SCRIPT = True
#----------------------------------------------------------------
# import 
import collections


# PyQt
from PyQt5 import *
from PyQt5.QtWidgets import *

# IDA Python SDK

import idaapi
import idc
import ida_ida
import ida_funcs
import idautils
import ida_kernwin
from idaapi import Form


# --- Log
def frn_log(entry, name='frn'):
    idaapi.msg("[" + name + "]: " + entry + "\n")

# --- Helpers
class FuncReName_HELPERS:
    # Menu 

    MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])

    class IdaMenuActionHandler(idaapi.action_handler_t):
        def __init__(self, handler, action):
            idaapi.action_handler_t.__init__(self)
            self.action_handler = handler
            self.action_type = action
    
        def activate(self, ctx):
            if ctx.widget_type == idaapi.BWN_DISASM:
                self.action_handler.handle_menu_action(self.action_type)
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


# --- Rename functions by log output view

class FuncReNameLogDiag(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:log_addr}
BUTTON YES* Enter
BUTTON CANCEL Cancel
Rename Function by log
Log func address and new function name in located .
<##Address\::{log_addr}>
<##Index\::{new_name}>
""", {
        'log_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'new_name': Form.NumericInput(swidth=20, tp=Form.FT_DEC),
        })
    

# --- Rname function by handle hook view---

class FuncRnameHookDiag(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:start_addr}
BUTTON YES* Enter
BUTTON CANCEL Cancel
Rename Function by log
Log func address and new function name in located .
<##StartEa\::{start_addr}>
<##EndEa\::{end_addr}>
<##off_func_addr\::{off_func_addr}>
<##off_next_new_name\::{off_new_name}>
""", {
        'start_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'end_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'off_new_name': Form.NumericInput(swidth=20, tp=Form.FT_DEC),
        'off_func_addr': Form.NumericInput(swidth=20, tp=Form.FT_DEC),
        })
        

class FuncReNamePlugin_t(idaapi.plugin_t, idaapi.UI_Hooks):
    
    popup_menu_hook = None
    
    flags = idaapi.PLUGIN_KEEP
    comment = "This is a comment"
    help = "This is help"
    wanted_hotkey = "Ctrl-Alt-N"
    plugin_name = "FuncReName"
    wanted_name = 'FuncReName'


    # --- PLUGIN LIFECRYCLE
    
    def __init__(self, name = 'FunReName' ):
        super(FuncReNamePlugin_t, self).__init__()
        frn_log("Install plugin {}".format(self.plugin_name))

        self.plugin_name = name
        self.wanted_name = name
        self.run()


    def init(self, name = 'FuncReName'):
        # super(FuncReNamePlugin, self).__init__()
        self.hook_ui_actions()

        frn_log("Init plugin {}".format(self.plugin_name))
        return idaapi.PLUGIN_KEEP
    
    def run(self, args=0):
        frn_log("Run plugin " + self.plugin_name)
        self.register_menu_actions()
        self.attach_main_menu_actions()

    def term(self):
        self.unhook_ui_actions()
        self.detach_main_menu_actions()
        self.unregister_menu_actions()
        frn_log("Unload plugin " + self.plugin_name)
    
    def unload_plugin(self): # synchronous unload (internal, Main
        
        self.detach_main_menu_actions()
        self.unregister_menu_actions()       

    # --- MAIN MENU
    
    MENU_ITEMS = []

    def isalpha_max(self, name):
        if name.isalpha() or name == '_':
            return True
        return False

    def get_new_func_name(self, log_func_addr, new_nm_index):
        frn_log("try get log args {:#x}".format(log_func_addr))
        args_list = idaapi.get_arg_addrs(log_func_addr)

        if args_list == None:
            frn_log("func argument is none , try set argument number")
            return False

        if len(args_list) < (new_nm_index+1):
            frn_log("func argument number is too small")
            return False
        
        if args_list[new_nm_index] > ida_ida.inf_get_max_ea():
            frn_log("func argument addr is not accessible")
            return False
                    
        name_addr = [ref for ref in idautils.DataRefsFrom(args_list[new_nm_index])]
        if len(name_addr) == 0:
            frn_log("can't get name addr")
            return False

        if len(name_addr) >= 2:
            name = idc.get_strlit_contents(name_addr[1])
        else:
            name = idc.get_strlit_contents(name_addr[0])

        if name == None:
            frn_log("new name is not string")
            return False

        #name = 'func_' + ''.join(x for x in name.decode() if x.isalpha()) # Keep only the letters
        name = 'func_' + ''.join(x for x in name.decode() if self.isalpha_max(x))
        frn_log("new_func_name {}".format(name))
        return name
    
    def get_call_logfunc_addr(self, log_addr):
        log_func_list = []
        for xref in idautils.XrefsTo(log_addr):
            log_func_list.append(xref.frm)
        
        return log_func_list

    def make_new_name(self, log_addr, new_nm_index):
  

        log_func_list = self.get_call_logfunc_addr(log_addr)
        for addr in log_func_list:
            # --- Check if the function needs to be renamed
            frn_log("call_addr: {:#x}".format(addr))
            old_name = idc.get_func_name(addr)
            # frn_log("old function name: {}".format(old_name))
            if 'func_' in old_name:
                frn_log("The function has been renamed")
                continue
            
            
            new_name = self.get_new_func_name(addr, new_nm_index)
            if new_name != False:
                func_attr = idc.get_func_attr(addr, idc.FUNCATTR_START)
                
                idc.set_name(func_attr, new_name)
                frn_log("func_addr: {:#x} new_func_name: {}".format(func_attr, new_name))
            else:
                continue

    def register_new_action(self, act_name, act_text, act_handler, shortcut, tooltip, icon):
        new_action = idaapi.action_desc_t(
            act_name,       # The action name. This acts like an ID and must be unique
            act_text,       # The action text.
            act_handler,    # The action handler.
            shortcut,       # Optional: the action shortcut
            tooltip,        # Optional: the action tooltip (available in menus/toolbar)
            icon)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(new_action)
    
    def handle_menu_action(self, action):
        [x.handler() for x in self.MENU_ITEMS if x.action == action]
  
    def register_menu_actions(self):
        self.MENU_ITEMS.append(FuncReName_HELPERS.MenuItem(self.plugin_name + ":LogFunc",             self.log_func,             "log_func",             "rename function by log function",           None,                   True    ))
        self.MENU_ITEMS.append(FuncReName_HELPERS.MenuItem(self.plugin_name + ":HookFunc",            self.hook_func,            "hook_func",            "rename function by hook functin",           None,                   True    ))
        self.MENU_ITEMS.append(FuncReName_HELPERS.MenuItem(self.plugin_name + ":MakeFunc",            self.make_udefind_func,    "make_undefined_func",  "make undefined function",                   None,                   True    ))

        self.add_custom_menu()

        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            self.register_new_action(item.action, item.title, FuncReName_HELPERS.IdaMenuActionHandler(self, item.action), item.shortcut, item.tooltip, -1)

    def unregister_menu_actions(self):
        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            idaapi.unregister_action(item.action)
    
    def attach_main_menu_actions(self):
        for item in self.MENU_ITEMS:
            idaapi.attach_action_to_menu("Edit/" + self.plugin_name + "/" + item.title, item.action, idaapi.SETMENU_APP)

    def detach_main_menu_actions(self):
        for item in self.MENU_ITEMS:
            idaapi.detach_action_from_menu("Edit/" + self.plugin_name + "/" + item.title, item.action)
    
    def add_custom_menu(self): # used by extensions
        pass

    # --- POPUP MENU

    def hook_ui_actions(self):
        self.popup_menu_hook = self
        self.popup_menu_hook.hook()

    def unhook_ui_actions(self):
        if self.popup_menu_hook != None:
            self.popup_menu_hook.unhook()

    # IDA 7.x
    def finish_populating_widget_popup(self, widget, popup_handle):
        if ida_kernwin.get_widget_type(widget) == idaapi.BWN_DISASM:
            for item in self.MENU_ITEMS:
                if item.popup:
                    idaapi.attach_action_to_popup(widget, popup_handle, item.action, self.plugin_name + "/")
    

    # --- METHONDS
    def make_udefind_func(self):
        ea = ida_ida.inf_get_min_ea()
        max_addr = ida_ida.inf_get_max_ea()
        while ea < max_addr:
            ea = idaapi.find_not_func(ea, idc.SEARCH_DOWN)
            ida_funcs.add_func(ea)       


    def log_func(self, address = 0, new_name = 0):
        # --- init ui windows
        logDlg = FuncReNameLogDiag()
        logDlg.Compile()
        logDlg.log_addr.value = address
        logDlg.new_name.value = new_name
        ok = logDlg.Execute()
        # init log_address and new_name index
        if ok == 1:
            log_addr     =     logDlg.log_addr.value
            new_nm_index = logDlg.new_name.value
            
            # call loop funciton 
            self.make_new_name(log_addr, new_nm_index)
        









    def hook_func(self, start_addr = 0, end_addr = 0, off_new_name = 8, off_func_addr = 4):

        def make_new_name(start_addr, end_addr, off_new_name, off_func_addr):
            # offset1 -> handle string -> get new func name
            # offset2 -> handle func   -> get func addr
            for addr in range(start_addr, end_addr, off_new_name):
                # first addr is string using to new func name
                name_addr = [ref for ref in idautils.DataRefsFrom(addr)]
                if len(name_addr) < 1:
                    frn_log("can't get name addr")
                    continue

                new_name = idc.et_strlit_contents(name_addr[0])
                frn_log("Get new func name is :{}".format(new_name))


                # Get the address of the function to be renamed
                # name_addr = [ref for ref in DataRefsFrom(0x5B200)][0]
                func_addr = [ref for ref in idautils.DataRefsFrom(addr+off_func_addr)][0]
                # for xref in idautils.XrefsFrom(addr+off_func_addr, 0):
                #     func_addr = xref.to

                # --- Check if the function needs to be renamed
                old_name = idc.get_func_name(func_addr)
                if 'func_' in old_name:
                    frn_log("The function has been renamed")
                    continue

                name      = 'func_' + new_name.decode()
                frn_log("The new func name is :{}".format(new_name))
                frn_log("The func addr is :{:#x}".format(func_addr))
                idc.set_name(func_addr, name)

        # --- init ui windows
        hookDlg = FuncRnameHookDiag()
        hookDlg.Compile()
        hookDlg.start_addr.value = start_addr
        hookDlg.end_addr.value = end_addr
        hookDlg.off_new_name.value = off_new_name
        hookDlg.off_func_addr.value = off_func_addr
        ok = hookDlg.Execute()
        # init log_address and new_name index
        if ok == 1:
            start_addr     =     hookDlg.start_addr.value 
            end_addr       =     hookDlg.end_addr.value
            off_new_name   =     hookDlg.off_new_name.value
            off_func_addr  =     hookDlg.off_func_addr.value


    
        # --- call loop func
        make_new_name(start_addr, end_addr, off_new_name, off_func_addr)


def PLUGIN_ENTRY():
    return FuncReNamePlugin_t()

if FuncReName_USE_AS_SCRIPT:
    if __name__ == '__main__':
        ReName = FuncReNamePlugin_t()
        ReName.init()
        ReName.run()