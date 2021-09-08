#!/usr/bin/python3

TABLE_ITEM_CONSUME = 10

ulebs = ["ULeb128"]
# define extra ULeb128 constructors
for i in range(1, TABLE_ITEM_CONSUME):
    extra_uleb = f"ULeb128_{i+1}"
    print(f'{extra_uleb}: ULeb128 \tis ULeb128 {{}}')
    ulebs.append(extra_uleb)

print()

print("# terminator constructors")
for i in range(len(ulebs)):
    consume_size = i+1
    current_lebs = ulebs[:consume_size]
    lebs_consume = " ; ".join(current_lebs)
    lebs_print = '^" "^'.join(current_lebs)
    print(f'br_table_items: {lebs_print} is br_table_count={consume_size} & {lebs_consume} [ br_table_count = 0; ]{{}}')

print("# consume constructors")
lebs_consume=" ; ".join(ulebs)
lebs_print = '^" "^'.join(ulebs)+'^" "^br_table_items'
print(f'br_table_items: {lebs_print} is {lebs_consume} ; br_table_items [ br_table_count = br_table_count - {TABLE_ITEM_CONSUME}; ]{{}}')
