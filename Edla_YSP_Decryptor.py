#!/usr/bin/env python3
# Original by kuronosuFear and port to python 3 and modification for compatibility with YSP by Calliste
# Original repo https://github.com/kuronosuFear/Yokai-Watch-Elder
#
# Commands for Windows without entries -> python Edla_YSP_Decryptor_v2.py <file name.yke or .ysp>
# Commands for Windows with entries extraction -> python Edla_YSP_Decryptor_v2.py <file name.yke or .ysp> yes

import os
import sys
import errno


def dword2int(dword):
    return int.from_bytes(dword[:4], byteorder='little')


def is_plausible_table(watchData, startingOffset, max_entries=200000):

    L = len(watchData)

    if startingOffset + 4 > L:
        return False, 0

    n = dword2int(watchData[startingOffset:startingOffset + 4])
    if n <= 0 or n > max_entries:
        return False, 0

    table_end = startingOffset + 4 + n * 4
    if table_end > L:
        return False, 0

    offsets = [
        dword2int(watchData[startingOffset + 4 + i * 4: startingOffset + 4 + i * 4 + 4])
        for i in range(min(n, 10))
    ]

    if any(offsets[i] > offsets[i + 1] for i in range(len(offsets) - 1)):
        return False, 0

    if len(offsets) < 2:
        return False, 0

    entryOffset = offsets[0] + startingOffset
    if entryOffset + 4 > L:
        return False, 0

    sizeOfEntry = dword2int(watchData[entryOffset:entryOffset + 4])
    diff = offsets[1] - offsets[0]

    if sizeOfEntry + 4 != diff:
        return False, 0

    return True, n


def find_starting_offset(watchData):
    known_candidates = [1048576, 0x60000]  # 1 Mo, 384 Ko

    for candidate in known_candidates:
        ok, n = is_plausible_table(watchData, candidate)
        if ok:
            return candidate, n

    return None, 0


if len(sys.argv) < 2:
    print("Use: python Edla_YSP_Decryptor.py <file name.yke or .ysp> [yes]")
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

if not doExtract:
    print("Decryption complete")
    sys.exit(0)

print("Comparing first 4-bytes to the marker")

if dword2int(watchData[:4]) == marker:
    print('Correct File Found!')
else:
    print('Incorrect File Found... Aborting')
    sys.exit(1)

print("Detecting entry table offset...")
StartingOffset, numberOfEntries = find_starting_offset(watchData)

if StartingOffset is None:
    print("Could not locate a plausible entry table in this file. Aborting.")
    sys.exit(1)

print(f"Entry table found at offset {StartingOffset} (0x{StartingOffset:x})")
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

written = 0
skipped = 0

for entryNum in range(1, numberOfEntries + 1):
    entryOffset = dword2int(
        watchData[StartingOffset + entryNum * 4:StartingOffset + entryNum * 4 + 4]
    ) + StartingOffset
    sizeOfEntry = dword2int(watchData[entryOffset:entryOffset + 4])
    end = entryOffset + 4 + sizeOfEntry

    if entryOffset < 0 or end > len(watchData) or sizeOfEntry < 0:
        skipped += 1
        continue

    with open(path + "%08d" % (entryNum,) + entryExt, 'wb') as fo:
        fo.write(watchData[entryOffset:end])
    written += 1

print(f"Extracting done : {written} written files, {skipped} entrees ignorees")
