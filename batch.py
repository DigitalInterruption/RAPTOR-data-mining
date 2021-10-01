import os

from process import processBin

# Create file list to be used for the batch processing by scanning input dir
def getFileList(src):
    classes = os.listdir(src)
    fList = []
    for c in classes:
        cPath = src + c + '/'
        if os.path.isdir(cPath):
            samples = os.listdir(cPath)
        for s in samples:
            fList.append(c + '/' + s)
    return fList

# Set data directories
inputDir = 'source/'
outputDir = 'dataset/'

# Get file list from input dir using function
flist = getFileList(inputDir)

# Iterate through each sample calling the process binary function
for i, f in enumerate(flist):
    print(f)
    processBin(f, inputDir, outputDir)

