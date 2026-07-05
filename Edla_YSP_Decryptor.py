#!/usr/bin/env python3
# Original by kuronosuFear and port to python 3 and modification for compatibility with YSP by Calliste
# Original repo https://github.com/kuronosuFear/Yokai-Watch-Elder
# Commands for Windows without entries -> python Elda_YSP_Decryptor.py <file name.yke or .ysp>
# Commands for Windows with entries extraction -> python Elda_YSP_Decryptor.py <file name.yke or .ysp> yes

import os
import sys
import errno


def dword2int(dword):
    return int.from_bytes(dword[:4], byteorder='little')


if len(sys.argv) < 2:
    print("Use: python Elda_YSP_Decryptor.py <file name.yke or .ysp> [yes]")
    sys.exit(1)

inputFile = sys.argv[1]

doExtract = len(sys.argv) >= 3 and sys.argv[2].lower() == 'yes'

base, ext = os.path.splitext(inputFile)
ext = ext.lower()

if ext == '.yke':
    outputFile = base + '.yked'
    marker = 0x004b0059
    entryExt = '.ykx'
elif ext == '.ysp':
    outputFile = base + '.yspd'
    marker = 0x00530059
    entryExt = '.ysx'
else:
    print(f"Unknown extension : {ext} (need .yke or .ysp)")
    sys.exit(1)

with open(inputFile, 'rb') as f:
    rawData = f.read()
    print("Loading file...")

XORkeyOffset = 96
XORkey = rawData[XORkeyOffset:XORkeyOffset + 32]
index = 0
watchData = bytearray()

for x in range(len(rawData)):
    watchData.append(rawData[x] ^ XORkey[index])
    index = index + 1
    if index >= 32:
        index = 0

with open(outputFile, 'wb') as fo:
    fo.write(watchData)

watchData = bytes(watchData)

StartingOffset = 1048576

if not doExtract:
    print("Decryption complete")
    sys.exit(0)

print("Comparing first 4-bytes to the marker")

if dword2int(watchData[:4]) == marker:
    print('Correct File Found!')
else:
    print('Incorrect File Found... Aborting')
    sys.exit(1)

numberOfEntries = dword2int(watchData[StartingOffset:StartingOffset + 4])
print(str(numberOfEntries) + " entries found")

StartOfData = (numberOfEntries * 4) + 4 + StartingOffset

path = input("Give here the name of the folder to create that contains all the entries : ").strip()
if path and not path.endswith(os.sep):
    path += os.sep

if path and not os.path.exists(os.path.dirname(path)):
    try:
        os.makedirs(os.path.dirname(path))
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise

for entryNum in range(1, numberOfEntries + 1):
    entryOffset = dword2int(
        watchData[StartingOffset + entryNum * 4:StartingOffset + entryNum * 4 + 4]
    ) + StartingOffset
    sizeOfEntry = dword2int(watchData[entryOffset:entryOffset + 4])
    with open(path + "%08d" % (entryNum,) + entryExt, 'wb') as fo:
        fo.write(watchData[entryOffset : entryOffset + 4 + sizeOfEntry])

print("Extracting done")