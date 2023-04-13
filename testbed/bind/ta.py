import fileinput
import re

print("trust-anchors {")

for line in fileinput.input(encoding="utf-8"):
    ta = line.split()
    print(f'"{ta[0]}" initial-ds {ta[4]} {ta[5]} {ta[6]} "{ta[7]}";')

print("};")
