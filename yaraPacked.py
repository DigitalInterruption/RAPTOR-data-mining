'''
    Slightly modified to work within the disassembly framework, taken almost
        completely from Islem BOUZENIA at:

https://gist.github.com/islem-esi/cef15f99db844fe1cfe596656dfe9bb2#file-detect_packer_cryptor-py
'''

import yara

peid_rules = yara.compile('yara/packers/peid.yar')
packer_rules = yara.compile('yara/packers/packer.yar')
crypto_rules = yara.compile('yara/crypto/crypto_signatures.yar')

packers = ['AHTeam', 'Armadillo', 'Stelth', 'yodas', 'ASProtect', 'ACProtect', 'PEnguinCrypt', 
 'UPX', 'Safeguard', 'VMProtect', 'Vprotect', 'WinLicense', 'Themida', 'WinZip', 'WWPACK',
 'Y0da', 'Pepack', 'Upack', 'TSULoader'
 'SVKP', 'Simple', 'StarForce', 'SeauSFX', 'RPCrypt', 'Ramnit', 
 'RLPack', 'ProCrypt', 'Petite', 'PEShield', 'Perplex',
 'PELock', 'PECompact', 'PEBundle', 'RLPack', 'NsPack', 'Neolite', 
 'Mpress', 'MEW', 'MaskPE', 'ImpRec', 'kkrunchy', 'Gentee', 'FSG', 'Epack', 
 'DAStub', 'Crunch', 'CCG', 'Boomerang', 'ASPAck', 'Obsidium','Ciphator',
 'Phoenix', 'Thoreador', 'QinYingShieldLicense', 'Stones', 'CrypKey', 'VPacker',
 'Turbo', 'codeCrypter', 'Trap', 'beria', 'YZPack', 'crypt', 'crypt', 'pack',
 'protect', 'tect', 'NET'
]

def checkRules(fpath, inputDir):
    try:
      #the function match will return the list of detected cryptors
      matches = crypto_rules.match(inputDir + fpath)
      if matches:
        print('\t\tcryptors detected')
        print('\t\t\t',matches)
        return True
    except:
      #I always add this exception thing, because I don't know what could happen
      print('cryptor exception, you must read yara docs')
      
    #detect packers

    try:
      matches = packer_rules.match(inputDir + fpath)
      if matches:
        print('\t\tpackers detected')
        print('\t\t\t',matches)
        return True
    except:
      print('packer exception, you must read yara docs')

def checkPacker(fpath, inputDir):
    #next, we will try to match peid rules with an exe file
    try:
      matches = peid_rules.match(inputDir + fpath)
      if matches:
        for match in matches:
          for packer in packers:
            #this line is simply trying to see if one of the known packers has been detected
            if packer.lower() in match.rule.lower():
              print('\t\tpacker detected')
              print('\t\t\t', match.rule, packer)
              return True
    except:
      print('error', fpath, inputDir)

