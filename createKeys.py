import os

import pandas as pd

dataDir = 'dataset/'

# Scan supplied dir and create family keys listing each sample
families = os.listdir(dataDir)
for f in families:
    fList = os.listdir(dataDir + f + '/')
    fList = [fl.split('.')[0] for fl in fList if fl.split('.')[0] not in families]
    pd.DataFrame(fList, columns=[f]).to_csv(dataDir + f + '/' + f + '.csv', index=False)
