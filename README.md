# Custom disassembler for opcode sequence extraction
This custom disassembler script takes a portable executable file and extracts the opcode sequence to be used as input data for link analysis.

## Operation
Takes the memory mapped image of the executable and filters opcode mnemonics as a sequence to `csv` files in directories corresponding to their class.
Removes padding and gives warnings where processing could suggest erroneous disassembly.

Input data should be placed in the source directory with sub-directories containing samples corresponding to their class, if data is unclassified it should be placed in a single sub-directory (the name of which doesn't matter) to help with unified processing.

A mirror of the source directory will be created in the dataset directory as the output with each sample translated into a `csv` containing the opcode mnemonic sequence.

## Instructions
`debug` and `single` scripts can be used to process lone binaries into full instruction sequences or opcode sequences respectively.
`batch` is used for processing whole datasets of binaries into opcode sequences, skipping bad samples and warning against strange disassembler behaviour.
For the `batch` processing it is recommended when processing large datasets to cast the output to a file for review:
``` zsh
python batch.py > out.txt
```
The `createKeys` script scans the provided directory and creates key file for each class with the sample names.

