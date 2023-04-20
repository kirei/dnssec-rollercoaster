import fileinput
import re

print("trust-anchors {")

for line in fileinput.input(encoding="utf-8"):
    if line.startswith(";"):
        continue
    ta = line.split()
    print(f'"{ta[0]}" initial-ds {ta[3]} {ta[4]} {ta[5]} "{ta[6]}";')

print("};")
