import pefile
import distorm3
import csv

# Read binary into memory
def loadBinary(inputPath):
    return pefile.PE(inputPath)

# Read 'Magic' header and set corresponging instruction set
def getInstructionSet(pe):
    try: bitArch = pe.OPTIONAL_HEADER.Magic
    except:
        print('\tfailed to read magic number, defaulting to 32bit,\
            check sample')
        bitArch = 267
    if bitArch == 267:                  # = 0x10b (PE32)
        bits = distorm3.Decode32Bits
    elif bitArch == 523:                # = 0x20b (PE32+)
        bits = distorm3.Decode64Bits
    else:
        print('\tmagic number does not correspond to 32bit or 64bit instruction\
                set (this would not run), defaulting to 32bit, check sample')
        bits = distorm3.Decode32Bits
    return bits

# Read the opcodes from the .text section of the PE file
def readInstructions(pe):
    base = pe.OPTIONAL_HEADER.BaseOfCode
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    codeLen = base + pe.OPTIONAL_HEADER.SizeOfCode

    if base > ep or ep > codeLen:
        print('\tentry point is outside the code seciton, check sample',
                '\n\t\tlikely a result of obfuscation')

    return pe.get_memory_mapped_image()[base:codeLen]

# Turn those opcodes into a list of lines as lists of contained instructions
def decodeInstructions(pe, data):
    # Get offset for use by decoder
    offset = pe.OPTIONAL_HEADER.BaseOfCode
    offset += pe.OPTIONAL_HEADER.ImageBase
    # Get corresponding instruction set
    bits = getInstructionSet(pe)

    return distorm3.Decode(offset, data, bits)

# Clean data and write to csv
def writeOpcodes(inst, sName, outputDir):
    # Create oputput path from sample name
    outputPath = outputDir + sName + '.csv'
    # Create list for the cleaned data
    cleanedCode = []
    # Set filtering masks
    skipCode = 'cc'         # INT 3
    skipInvalid = 'DB 0'    # DB <hex> (not instruciton)
    paddingCode = '0000'    # ADD [EAX], AL (zero padding)
    invalidCode = '00'      # DB (trailing zero padding)

    validEnds = set(['jmp', 'ret'])

    # Clean sampled instructions down to standardised pure opcode instruction
    for l, line in enumerate(inst):
        # Collect instruction bytes for catching padding blocks
        code = line[3]
        # Skip line if function padding detected
        if code == skipCode: continue
        # Look for zero padding at the end of the seciton
        if code == paddingCode:
            if l+16 < len(inst): codes = [lines[3] for lines in inst[l:l+16]]
            else: codes = [lines[3] for lines in inst[l:len(inst)]]
            if all(c == paddingCode for c in codes): break
            elif codes[-2] == paddingCode and codes[-1] == invalidCode: break
        # Extract the hex instructions from the list
        instruction = line[2]
        # Skip line if error signifier is found
        if skipInvalid in instruction: continue
        # Get only the first word (instruction) in lower case
        cleanedCode.append(instruction.partition(' ')[0].lower())

    # Check the opcode sequence containes elements and skip writing if nor
    if len(cleanedCode) == 0:
        print('\tno valid opcodes extracted')
        return None

    if cleanedCode[-1] not in validEnds:
        print('\tinvalid ending opcode: ', cleanedCode[-1])
        return None

    # Write cleaned opcode sequence to csv file
    with open(outputPath, 'w', newline='') as csvfile:
        for line in cleanedCode: csv.writer(csvfile).writerow([line])

# Test function to write whole decoded instruction set to csv
def testingOutput(inst, outputPath, convertHex=False):
    # Convert address from int to hex for easier comparison with disassembler
    if convertHex:
        inst = [(hex(line[0]), line[1], line[2], line[3]) for line in inst]

    with open(outputPath, 'w', newline='') as f: csv.writer(f).writerows(inst)

