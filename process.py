import disas as ds
from yaraPacked import checkRules, checkPacker
from sectionChecker import checkPacked

def processBin(fpath, inputDir, outputDir):
    try: target = ds.loadBinary(inputDir + fpath)
    except:
        print('\tfailed to read sample, probably not a PE, skipping')
        return None
    if checkRules(fpath, inputDir):
        print('\tyara rules detected packing, skipping')
        return None
    if checkPacker(fpath, inputDir):
        print('\tpacker peid found by yara, skipping')
        return None
    if checkPacked(target, fpath, inputDir):
        print('\tsample is packed (or wont cleanly disassemble), skipping')
        return None
    try: sName = fpath.split('.')[0]
    except: sName = fpath

    instr = ds.readInstructions(target)

    decoded = ds.decodeInstructions(target, instr)
    ds.writeOpcodes(decoded, sName, outputDir)

def debugBin(fpath):
    target = ds.loadBinary(fpath)
    sName = fpath.split('/')[-1]

    instr = ds.readInstructions(target)

    decoded = ds.decodeInstructions(target, instr)
    ds.testingOutput(decoded, sName + '.csv', True)
