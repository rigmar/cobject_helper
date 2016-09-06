from idaapi import IDA_SDK_VERSION
import idaapi
from idautils import *
if IDA_SDK_VERSION >= 695:
    from idc import *
    from ida_hexrays import *
    from ida_kernwin import *
    from ida_idaapi import *
    from ida_bytes import *
    from ida_lines import *
    from ida_typeinf import *
    from ida_struct import *
    from ida_funcs import *
else:
    from idaapi import *
    from idc import *

fDebug = False
if fDebug:
    import pydevd

create_struct_actname = "cobject_helper:create_struct"
create_vtable_actname = "cobject_helper:create_vtable"
def isMangled(name):
    if name.startswith("_ZN"): return True
    return False

def GetXrefCnt(ea):
    i = 0
    for xref in XrefsTo(ea,0):
        i +=1
    return i

def create_vtable(addr):
    print "addr = 0x%08X"%addr
    name = AskStr("","Please enter the class name")
    if name == None:
        return
    struct_id = GetStrucIdByName(name+"_vtbl")
    #print struct_id
    if struct_id != BADADDR:
        i = AskYN(0,"A vtable structure for %s already exists. Are you sure you want to remake it?"%name)
        if i==BADADDR:
            return
        if i==1:
            DelStruc(struct_id)
            struct_id = AddStrucEx(BADADDR,name+"_vtbl",0)
    else:
        struct_id = AddStrucEx(BADADDR,name+"_vtbl",0)
    if struct_id == BADADDR:
        Warning("Could not create the vtable structure!.\nPlease check the entered class name.")
        return

    #bNameMethods = AskYN(0,"Would you like to assign auto names to the virtual methods (%s_virtXX)?"%name)
    i = 0
    while (isFunc(getFlags(Dword(addr))) and (GetXrefCnt(addr) == 0 or i == 0)) is True:
        c = Dword(addr)
        methName = ""
        print "c = 0x%08X"%c
        print "i = %d"%i
        if c !=0:
            if hasName(c) or Name(c) != "":
                methName = Name(c)
                if isMangled(methName):
                    methName = Demangle(methName,0)[:Demangle(methName,0).find("(")]
                    methName = methName.replace("~","dtor_").replace("==","_equal")
            else:
                methName = name + "__" + "virt_%X"%c
        else:
            methName = "field_%02X"%(i*4)
        print methName
        e = AddStrucMember(struct_id,methName,i*4,FF_0OFF|FF_DWRD|FF_DATA,BADADDR,4)
        print "e = %d"%e
        if e != 0:
            if e == -1:
                l = 0
                while e == -1:
                    e = AddStrucMember(struct_id,(methName + ("_%d")%l),i*4,FF_0OFF|FF_DWRD|FF_DATA,BADADDR,4)
                    l = l + 1
            elif e != -2 and e != BADADDR:
                Warning("Error adding a vtable entry!")
                return
            else:
                print "PIZDEC!"
                return
        SetMemberComment(struct_id,i*4,"-> %08X, args: 0x%X"%(c,GetFrameArgsSize(c)),1)
        i = i + 1
        addr = addr +4
    return name+"_vtbl"

class ItemContainer(object):
    def __init__(self,item,parent,item_is_expr,parent_is_expr):
        self.parent = parent
        self.item = item
        self.parent_is_expr = parent_is_expr
        self.item_is_expr = item_is_expr

class create_vtable_action_handler_t(action_handler_t):
    def __init__(self):
        action_handler_t.__init__(self)
        self.items = []

    def activate(self, ctx):
        if fDebug:
            pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True)
        my_ti = idaapi.cvar.idati
        vdui = get_tform_vdui(ctx.form)
        vdui.get_current_item(USE_KEYBOARD)
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            name = create_vtable(target_item.obj_ea)
            if name is not None:
                self.walk_ctree(vdui.cfunc)
                it = self.get_item_container(target_item)
                if it is not None:
                    it_parent_idx = self.get_parent_idx(it)
                    while it_parent_idx != None:
                        it_parent = self.items[it_parent_idx]
                        if it_parent.item_is_expr and it_parent.item.opname == "asg":
                            operand = it_parent.item.cexpr.x
                            if operand.opname == "memptr":
                                off = operand.cexpr.m
                                it_obj = operand.cexpr.x
                                obj_name = ("%s"%it_obj.cexpr.type).strip(" *")
                                sid = GetStrucIdByName(obj_name)
                                if sid == BADADDR:
                                    break
                                sptr = get_struc(sid)
                                mptr = get_best_fit_member(sptr,off)
                                tif = tinfo_t()
                                parse_decl2(my_ti,name + " *;",tif,0)
                                set_member_tinfo2(sptr,mptr,0,tif,0)
                                break
                        it_parent_idx = self.get_parent_idx(it_parent)

        detach_action_from_popup(ctx.form,create_vtable_actname)
        return 1

    def update(self, ctx):
        #print "Update"
        vdui = get_tform_vdui(ctx.form)
        if vdui:
            return AST_ENABLE_FOR_FORM
        else:
            return AST_DISABLE_FOR_FORM

    def get_parent_idx(self,target_item):
        for item in self.items:
            if target_item.parent is not None:
                if target_item.parent_is_expr == item.item_is_expr:
                    if item.item == target_item.parent:
                        return self.items.index(item)
            else:
                break
        return None

    def get_item_container(self,item):
        for it in self.items:
            if it.item_is_expr == item.is_expr() and it.item == item:
                return it
        return None

    def walk_ctree(self, cfunc):
        self.items = []
        self.cfunc = cfunc
        #if fDebug:
        #    pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True)
        print "walk_ctree"
        root = None
        class visitor(ctree_visitor_t):

            def __init__(self,obj, cfunc):
                ctree_visitor_t.__init__(self,CV_PARENTS)
                self.cfunc = cfunc
                self.obj = obj
                return

            def visit_insn(self, i):
                #print "\nvisit_insn"
                #print "item:"
                #print i,'\n'
                parent = None
                #print "Parents:\n",self.parents
                #print "Items:\n",self.obj.items
                if len(self.parents) > 1:
                    parent = self.parents[len(self.parents)-1]
                    #print parent.cinsn
                    #print parent in self.obj.items
                if parent is not None:
                    if parent.is_expr():
                        cur_item = ItemContainer(i,parent.cexpr,False,True)
                    else:
                        cur_item = ItemContainer(i,parent.cinsn,False,False)
                else:
                    cur_item = ItemContainer(i,parent,False,False)
                self.obj.items.append(cur_item)
                return 0 # continue enumeration
            def visit_expr(self, i):
                #print "\nvisit_expr"
                #print "item:"
                #print i,'\n'
                parent = None
                #self.obj.items.append(i)
                #self.obj.G.add_node(self.obj.items.index(i))
                #print "Parents:\n",self.parents
                #print "Items:\n",self.obj.items
                if len(self.parents) > 1:
                    parent = self.parents[len(self.parents)-1]
                    #print parent.cinsn
                if parent.is_expr():
                    cur_item = ItemContainer(i,parent.cexpr,True,True)
                else:
                    cur_item = ItemContainer(i,parent.cinsn,True,False)
                self.obj.items.append(cur_item)
                return 0

        visitor(self,cfunc).apply_to(cfunc.body, None)



def create_struct(struc_size=0):
    name = ""
    name = AskStr(name,"Please enter the struct name")
    if name is None or len(name) == 0:
        return
    FieldsNum = 0
    if struc_size > 0:
        FieldsNum = struc_size
    else:
        FieldsNum = AskLong(FieldsNum,"Size of your structure?")
    if FieldsNum == 0 or FieldsNum is None:
        return
    #elif FieldsNum%4 != 0:
    #    FieldsNum = FieldsNum + (4 - FieldsNum%4)
    #FieldsNum /= 4
    FieldsNum, pad = divmod(FieldsNum,4)
    print "FieldsNum = %d"%FieldsNum
    struct_id = GetStrucIdByName(name)
    if struct_id != BADADDR:
        answer = AskYN(0,"A structure for %s already exists. Are you sure you want to remake it?"%name)
        if answer == 1:
            DelStruc(struct_id)
        else:
            return
    struct_id = AddStrucEx(-1,name,0)
    if struct_id == BADADDR:
        Warning("Could not create the structure!.\nPlease check the entered name.")
        return
    i = 0
    for i in range(0,FieldsNum):
        if AddStrucMember(struct_id,"field_%X"%(i*4),-1,FF_DWRD|FF_DATA,-1,4) != 0:
            Warning("Error adding member")
            return
        if i%500 == 0:
            print "Current field %d"%i
    if pad == 2:
        if AddStrucMember(struct_id,"field_%X"%(i*4+4),-1,FF_WORD|FF_DATA,-1,2) != 0:
            Warning("Error adding member")
            return
    elif pad == 1:
        if AddStrucMember(struct_id,"field_%X"%(i*4+4),-1,FF_BYTE|FF_DATA,-1,1) != 0:
            Warning("Error adding member")
            return
    elif pad == 3:
        if AddStrucMember(struct_id,"field_%X"%(i*4+4),-1,FF_WORD|FF_DATA,-1,2) != 0:
            Warning("Error adding member")
            return
        if AddStrucMember(struct_id,"field_%X"%(i*4+6),-1,FF_BYTE|FF_DATA,-1,1) != 0:
            Warning("Error adding member")
            return

    return

class create_struct_action_handler_t(action_handler_t):
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        vdui = get_tform_vdui(ctx.form)
        vdui.get_current_item(USE_KEYBOARD)
        struc_size = 0
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            if target_item.opname == "num":
                s = tag_remove(target_item.cexpr.print1(None)).rstrip("u")
                if s.startswith("0x"):
                    struc_size = int(s,16)
                else:
                    struc_size = int(s,10)
        create_struct(struc_size)
        return 1

    def update(self, ctx):
        #print "Update"
        vdui = get_tform_vdui(ctx.form)
        if vdui:
            return AST_ENABLE_FOR_FORM
        else:
            return AST_DISABLE_FOR_FORM


def get_func_by_name(name):
    for i in range(0,get_func_qty()):
        func = getn_func(i)
        if get_func_name2(func.startEA) == name:
            return func
    return None

def cb(event, *args):
    if event == hxe_populating_popup:
        #print "event_callback: hxe_populating_popup"
        form, phandle, vu = args
        res = attach_action_to_popup(vu.ct, None, create_struct_actname)
        vu.get_current_item(USE_KEYBOARD)
        if vu.item.is_citem() and vu.item.it.is_expr():
            item = vu.item.e
            if item.opname == "obj":
                res = attach_action_to_popup(vu.ct, phandle, create_vtable_actname)
                return 0
        detach_action_from_popup(vu.form,create_vtable_actname)
    if event == hxe_double_click:
        vu, shift_state = args
        vu.get_current_item(USE_KEYBOARD)
        if vu.item.is_citem() and vu.item.it.is_expr():
            item = vu.item.e
            if item.opname == "memptr":
                off = item.cexpr.m
                it_obj = item.cexpr.x
                obj_name = ("%s"%it_obj.cexpr.type).strip(" *")
                sid = GetStrucIdByName(obj_name)
                if sid != BADADDR:
                    sptr = get_struc(sid)
                    mptr = get_best_fit_member(sptr,off)
                    addr = get_member_cmt(mptr.id,1)
                    if addr is not None and addr.startswith("-> "):
                        addr = int(addr.split(",")[0].strip("-> "),16)
                        decompiled_window = open_pseudocode(addr, -1)
                    else:
                        func_name = get_member_name2(mptr.id)
                        func = get_func_by_name(func_name)
                        if func is not None:
                            decompiled_window = open_pseudocode(func.startEA, -1)


    return 0


class cobject_helper_plugin_t(plugin_t):
    flags = PLUGIN_HIDE
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "cobject_helper"
    #wanted_hotkey = "Alt-F8"
    wanted_hotkey = ""

    def init(self):
        print("cobject_helper init() called!\n")
        if init_hexrays_plugin():
            register_action(
                action_desc_t(
                    create_struct_actname,
                    "Create struct",
                    create_struct_action_handler_t(),
                    "shift+C"))
            register_action(
                action_desc_t(
                    create_vtable_actname,
                    "Create vtable",
                    create_vtable_action_handler_t(),
                    "shift+V"))

            install_hexrays_callback(cb)
            return PLUGIN_KEEP
        else:
            print 'print_ctree: hexrays is not available.'
            return PLUGIN_SKIP

    def run(self, arg):
        print("cobject_helper run() called with %d!\n" % arg)
        #require('flare')
        #require('flare.struct_typer')
        #struct_typer.main()
        pass


    def term(self):
        print("cobject_helper term() called!\n")
        pass

def PLUGIN_ENTRY():
    print "PLUGIN_ENTRY"
    return cobject_helper_plugin_t()


