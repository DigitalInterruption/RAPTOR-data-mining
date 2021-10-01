import disas as ds
import csv

pe = ds.loadBinary('./calc.exe')

memData = pe.get_memory_mapped_image()[pe.OPTIONAL_HEADER.BaseOfCode:\
        pe.OPTIONAL_HEADER.BaseOfCode + pe.OPTIONAL_HEADER.SizeOfCode]
memInst = ds.decodeInstructions(pe, memData)
memInst = [(hex(inst[0]), inst[1], inst[2], inst[3]) for inst in memInst]
with open('memInst.csv', 'w', newline='') as f:
     writer = csv.writer(f)
     writer.writerows(memInst)

txtData = pe.sections[0].get_data()
txtInst = ds.decodeInstructions(pe, txtData)
txtInst = [(hex(inst[0]), inst[1], inst[2], inst[3]) for inst in txtInst]
with open('txtInst.csv', 'w', newline='') as f:
     writer = csv.writer(f)
     writer.writerows(txtInst)

print('done, play around with mem and txt (Data and Inst)')
