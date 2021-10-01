import os
import csv

from collections import Counter

target = '../dataset-VXAPT/'

sets = os.listdir(target)

ignore = set(['Dockerfile','.dockerignore','.github','.git'])

codes = []

for s in sets:
    if s in ignore: continue
    spath = target + s + '/'
    files = os.listdir(spath)
    for f in files:
        if s in f: continue
        fpath = spath + f
        print(s + '/' + f)
        sample = []
        with open(fpath, 'r') as file:
            reader = csv.reader(file, delimiter='\n')
            [sample.append(line[0]) for line in reader]
        print('\t',sample[-1])
        codes.append(sample[-1])

counter = Counter(codes)
print([[list(counter.keys())[i], list(counter.values())[i]]
    for i in range(len(counter.keys()))])
