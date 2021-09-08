#!/usr/bin/python3

INDENT_CONSUME = 20

INDENT_PATTERN = " . "

print("# terminator constructors")
print('indent: "" is indent_lvl=0 {}')
for i in range(INDENT_CONSUME):
    consume_size = i+1
    indents = consume_size*INDENT_PATTERN
    print(f'indent: "{indents}" is indent_lvl={consume_size} [ indent_lvl=0; ]{{}}')

print("# consume constructors")
indents = INDENT_CONSUME*INDENT_PATTERN
print(f'indent: "{indents}"^indent is indent [ indent_lvl=indent_lvl-{INDENT_CONSUME}; ]{{}}')

print()
print()

print("# This outputs one less indentation than indent, use this when the indent_lvl is increased by the current instruction")
print()

print("# terminator constructors")
print('inc_indent: "" is indent_lvl=1 | indent_lvl=0 {}')
for i in range(INDENT_CONSUME-1):
    consume_size = i+1
    indents = consume_size*INDENT_PATTERN
    print(f'inc_indent: "{indents}" is indent_lvl={consume_size+1} [ indent_lvl=0; ]{{}}')

print("# consume constructors")
indents = (INDENT_CONSUME-1)*INDENT_PATTERN
print(f'inc_indent: "{indents}"^inc_indent is inc_indent [ indent_lvl=indent_lvl-{INDENT_CONSUME}; ]{{}}')

