# My IDApython cheat sheet (IDA 7.5 / python3)

## By keyboard shortcut (see below for context) :

  * `:` : `idc.set_cmt(ea, "string", 0)` 
  * `;` : `idc.set_cmt(ea, "string", 1)` 
  * `N` : `idc.set_name(ea, "New_name")`
  * `U` : `ida_bytes.del_items(ea, 0, 1) # do it 1 by 1 byte`
  * `C` : `ida_ua.create_insn(ea)`
  * `D` : `ida_bytes.create_data(ea, idc.FF_DWORD, 4, idaapi.BADADDR)`
  * `*` : `idc.make_array(ea, n)`
  * `A` : `ida_bytes.create_strlit(ea, size, 0)`
  * `Y` : `idc.SetType(ea, "type")`
  * `M` : `idc.op_enum(ea, n, enum_id, 0)`
  * `T` : `idc.op_stroff(ea, 0, struc_id, 0)`
  * `H` : `idc.op_hex(ea, n)` / `idc.op_dec(ea, n)`
  * `R` : `idc.op_chr(ea, n)`
  * `B` : `idc.op_bin(ea, n)`
  * `_` : `toggle_sign(ea, n)`
  * `Ctrl+X` : `[x.frm for x in idautils.XrefsTo(ea)]`

## Basics

Imports :
```python
import idc
import idaapi
import idautils
import ida_bytes
import ida_ua
```

Current cursor position :
```
idc.here()
```

Read memory :
```python
ida_bytes.get_bytes(ea, size)
```

Cross References (shortcut : Ctrl-X) :
```python
for xref in idautils.XrefsTo(ea):
    print(xref.frm, xref.type)

# XrefsTo(ea, type)
# Types : ida_xref.XREF_ALL, ida_xref.XREF_DATA,  ida_xref.XREF_FAR
```

## Comments and Names

Comments (shortcut : ':' and ';') :
```python
idc.set_cmt(ea, "string", 0) # 1 for repeatable
idc.get_cmt(ea, 0) # or 1 ...
```

Renaming an address (shortcut : 'N') :
```python
idc.set_name(ea, "New_name")
idc.get_name(ea)
```

## Types

Undefine (shortcut : 'U') :
```python
ida_bytes.del_items(ea, 0, 1) # do it 1 by 1 byte
```

Make code (shortcut : 'C') :
```python
ida_ua.create_insn(ea)
ea += idc.get_item_size(ea) # to loop
```

Make data (shortcut : 'D') :
```python
ida_bytes.create_data(ea, idc.FF_XX, size, idaapi.BADADDR)
# idc.FF_BYTE  : size 1
# idc.FF_WORD  : size 2
# idc.FF_DWORD : size 4
# idc.FF_QWORD : size 8

ida_bytes.create_byte(ea, size, 1) # make a byte array of size long
```

Make string (shortcut : 'A') :
```python
ida_bytes.create_strlit(ea, size, type_str)

# type :
#     Cstring : 0
#     Wstring : idc.STRTYPE_C_16
```

Make array (shortcut : '*') :
```python
idc.make_array(ea, n)
```

Define custom type (shortcut : 'Y') :
```python
idc.SetType(ea, "type")
```

Get function pointer prototype from IDA database:
```python
f_t = idaapi.get_named_type(None, "FunctionName", 0)
i_tif = idaapi.tinfo_t()
i_tif.deserialize(None, f_t[1], f_t[2])
ptr_proto = str(i_tif).replace("__stdcall", f"(__stdcall *)")
```

**Bug correction :** after changing the type of something to a function ptr, force IDA to reanalyse the parameters
```python
for x in idautils.XrefsTo(ea, 0):
    if idc.print_insn_mnem(x.frm) == "call":
        ida_bytes.set_forced_operand(x.frm, 0, "")
        idaapi.request_refresh(0xFFFFFFFF)
```

## Instructions

Moving between instructions :
```python
prev_ea = idc.prev_head(ea)
next_ea = idc.next_head(ea)
if next_ea == idc.BADADDR:
    print("no next")
```

Get disassembly :
```python
idc.GetDisasm(ea) # returns "mov     eax, 0x23"
idc.print_insn_mnem(ea) # returns "mov"
idc.print_operand(ea, n) # return operand string (0:"eax", 1:"0x23")
```

Read operands :
```python
idc.get_operand_type(ea, n)
idc.get_operand_value(ea, n)
```

Get call destination (the dirty way) :
```python
dest = list(idautils.XrefsFrom(call_ea))[1].to
```

Change operand representation (shortcut : 'H', 'R', '_', 'B'):
```
idc.op_hex(ea, n)
idc.op_dec(ea, n)
idc.op_chr(ea, n)
idc.op_bin(ea, n)
toggle_sign(ea, n)
```

## Structures

Get struc by name :
```python
struc_id = idc.get_struc_id("struc_NAME")
if struc_id == idaapi.BADADDR:
    struc_id = idc.add_struc(0, "struc_NAME", 0)
```

Delete :
```python
idc.del_struc(idc.get_struc_id("struc_NAME"))
```

Member :
```python
idc.add_struc_member(struc_id, "field_name", offset, idc.FF_DWORD, idaapi.BADADDR, 4)
# See before for idc.FF_XXX constants
# Size superior to the type will create an array (multiple of type size)

idc.del_struc_member(struc_id, offset)

idc.get_member_name(struc_id, offset)
idc.set_member_name(struc_id, offset, "new_name")

idc.get_member_size(struc_id, offset)
```

Apply struc offset to operand (shortcut : 'T'):
```python
idc.op_stroff(ea, 0, struc_id, 0)
```

Comments :
```python
idc.set_member_cmt(struc_id, offset, "comment", 0) # 1 for reapeatable
idc.get_member_cmt(struc_id, offset, 0)
```

Xrefs :
```python
XrefsTo(struc_id) # Xref to the usage of (sizeof struc)
XrefsTo(idc.get_member_id(struc_id, offset)) # Xref to a struc field
```

Change member type (shortcut : 'Y') :
```python
idc.SetType(idc.get_member_id(struc_id, offset), "type")
```

## Enums

Get enum by name :
```python
enum_id = idc.get_enum("ENUM_NAME")
if enum_id == idc.BADADDR:
    enum_id = idc.add_enum(0, "ENUM_NAME", idaapi.hex_flag()) # idaapi.dec_flag() to show decimals
```

Delete :
```python
idc.del_enum(idc.get_enum("ENUM_NAME"))
```

Member :
```python
idc.add_enum_member(enum_id, "NAME", 12, -1)
enum_value_id = idc.get_enum_member(enum_id, value, 0, 0) # Get by value
enum_value_id = idc.get_enum_member_by_name("NAME") # Get by name
```

Apply to instruction operand (shortcut : 'M'):
```python
idc.op_enum(ea, n, enum_id, 0) # n = operand number
```

Comments :
```python
# for members :
idc.set_enum_member_cmt(enum_value_id, "comment", 0) # 1 for repeatable
idc.get_enum_member_cmt(enum_value_id, 0)

# For the enum itsef :
idc.set_enum_cmt(enum_id, "comment", 0)
idc.get_enum_cmt(enum_id, 0)
```

Xrefs :
```python
idautils.XrefsTo(enum_value_id)
```

## Functions 

Comments :
```
idc.set_funct_cmt(ea, "comment", 0)
idc.get_funct_cmt(ea, 0)
```