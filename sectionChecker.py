import r2pipe

# Get section entropy information as dictionary from json stream
def entropy(path):
    r = r2pipe.open(path)
    ent = r.cmdj('iSj entropy')
    return ent

# Composed by Islem BOUZENIA taken from:
#   https://gist.githubusercontent.com/islem-esi/334d223b3088e0bec5adc75f010c83c2/raw/f95fdbfece61ab42900c7d7f8b62e4264e5fabc1/detect_with_pefile.py
packers_sections = {
        #The packer/protector/tools section names/keywords
        '.aspack': 'Aspack packer',
        '.adata': 'Aspack packer/Armadillo packer',
        'ASPack': 'Aspack packer',
        '.ASPack': 'ASPAck Protector',
        '.boom': 'The Boomerang List Builder (config+exe xored with a single byte key 0x77)',
        '.ccg': 'CCG Packer (Chinese Packer)',
        '.charmve': 'Added by the PIN tool',
        'BitArts': 'Crunch 2.0 Packer',
        'DAStub': 'DAStub Dragon Armor protector',
        '!EPack': 'Epack packer',
        'FSG!': 'FSG packer (not a section name, but a good identifier)',
        '.gentee': 'Gentee installer',
        'kkrunchy': 'kkrunchy Packer',
        '.mackt': 'ImpRec-created section',
        '.MaskPE': 'MaskPE Packer',
        'MEW': 'MEW packer',
        '.MPRESS1': 'Mpress Packer',
        '.MPRESS2': 'Mpress Packer',
        '.neolite': 'Neolite Packer',
        '.neolit': 'Neolite Packer',
        '.nsp1': 'NsPack packer',
        '.nsp0': 'NsPack packer',
        '.nsp2': 'NsPack packer',
        'nsp1': 'NsPack packer',
        'nsp0': 'NsPack packer',
        'nsp2': 'NsPack packer',
        '.packed': 'RLPack Packer (first section)',
        'pebundle': 'PEBundle Packer',
        'PEBundle': 'PEBundle Packer',
        'PEC2TO': 'PECompact packer',
        'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
        'PEC2': 'PECompact packer',
        'pec1': 'PECompact packer',
        'pec2': 'PECompact packer',
        'PEC2MO': 'PECompact packer',
        'PELOCKnt': 'PELock Protector',
        '.perplex': 'Perplex PE-Protector',
        'PESHiELD': 'PEShield Packer',
        '.petite': 'Petite Packer',
        'petite': 'Petite Packer',
        '.pinclie': 'Added by the PIN tool',
        'ProCrypt': 'ProCrypt Packer',
        '.RLPack': 'RLPack Packer (second section)',
        '.rmnet': 'Ramnit virus marker',
        'RCryptor': 'RPCrypt Packer',
        '.RPCrypt': 'RPCrypt Packer',
        '.seau': 'SeauSFX Packer',
        '.sforce3': 'StarForce Protection',
        '.spack': 'Simple Pack (by bagie)',
        '.svkp': 'SVKP packer',
        'Themida': 'Themida Packer',
        '.Themida': 'Themida Packer',
        'Themida ': 'Themida Packer',
        '.taz': 'Some version os PESpin',
        '.tsuarch': 'TSULoader',
        '.tsustub': 'TSULoader',
        '.packed': 'Unknown Packer',
        'PEPACK!!': 'Pepack',
        '.Upack': 'Upack packer',
        '.ByDwing': 'Upack Packer',
        'UPX0': 'UPX packer',
        'UPX1': 'UPX packer',
        'UPX2': 'UPX packer',
        'UPX!': 'UPX packer',
        '.UPX0': 'UPX Packer',
        '.UPX1': 'UPX Packer',
        '.UPX2': 'UPX Packer',
        '.vmp0': 'VMProtect packer',
        '.vmp1': 'VMProtect packer',
        '.vmp2': 'VMProtect packer',
        'VProtect': 'Vprotect Packer',
        '.winapi': 'Added by API Override tool',
        'WinLicen': 'WinLicense (Themida) Protector',
        '_winzip_': 'WinZip Self-Extractor',
        '.WWPACK': 'WWPACK Packer',
        '.yP': 'Y0da Protector',
        '.y0da': 'Y0da Protector',
    }
#lower case the names to make it easier for search
packers_sections_lower =  {x.lower(): x for x in packers_sections.keys()}

# Check section names do not match those of known packers
def detectPacking(sections_of_pe):
    return 1 in [packers_sections_lower[x.lower()] for x in sections_of_pe
            if x.lower() in packers_sections_lower.keys()]

# Check list contains sequential elements
def checkConsecutive(l):
    return sorted(l) == list(range(min(l), max(l) + 1))

# Run checks for packed sample
def checkPacked(exe, fpath, inputDir):
    ent = entropy(inputDir + fpath)
    sect= []
    for i, s in enumerate(ent['sections']):
        # Exception handling for samples entropy cannot be calculated for
        try: sEnt = float(s['entropy'])
        except KeyError: sEnt = 0.0
        # Check the entropy value of the (executable) section is below 6.7
        if 'x' in s['perm'] and (sEnt > 6.7 or sEnt == 0): 
            print('\t\tcondition 1')
            return True
        # Check the name does not contain mask elements
        elif detectPacking([
            section.Name.decode(errors='replace',).rstrip('\x00')
            for section in exe.sections]):
            print('\t\tcondition 2')
            return True
        # Record seciton number if executable
        if 'x' in s['perm']: sect.append(i)
    # Check there are executable sections
    if len(sect) == 0:
        print('\t\tcondition 3')
        return True
    # Check executable sections are sequential
    if not checkConsecutive(sect): 
        print('\t\tcondition 4')
        return True
    # Return false if none of the conditions are met
    return False

