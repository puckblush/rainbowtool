import argparse
from os.path import isfile
import hashlib
import binascii

class hashes():
    def __init__(self):
        self.supported = ["ntlm","md5","sha256"]
    def list_hashes(self):
        print("Supported hash types : ")
        for alg in self.supported:
            print("$ " + alg)
    def ntlm(self,text):
        resultHash = hashlib.new('md4', text.encode('utf-16le')).hexdigest()
        return resultHash
    def md5(self,text):
        resultHash = hashlib.md5(text.encode('utf-16le')).hexdigest()
        return resultHash
    def sha256(self,text):
        resultHash = hashlib.sha256(text.encode('utf-16le')).hexdigest()
        return resultHash
        
        
        
class rainbowtool():
    def __init__(self):
        pass
    def crack_with_rainbowtable(self,hashtocrack,rainbowtable,hashformat,verbose=False):
        for line in open(rainbowtable,'r'):
            line = line.strip()
            if hashtocrack in line:
                if line.count(":") != 1 and verbose:
                    print("[?] Encountered Invalid Line : " + line)
                else:
                    parsed = line.split(":")
                    computed_hash = parsed[0]
                    if computed_hash == hashtocrack:
                        password = parsed[1]
                        if verbose:
                            print("[!!!] CRACKED : " + password)
                        return password
        print("[---] Hash not in rainbow table") # If we reach here, it means that the hash could not be cracked
                        
    def make_rainbowtable(self,file,hashfunction,outfile=None):
        # makes the output file if it doesn't exist
        if outfile != None:
            if not isfile(outfile):
                open(outfile,'x').close()
            fileHandler = open(outfile,'a')
            
        for line in open(file,'r',errors='ignore'): # Ignores invalid characters because they're a headache to deal with, and the vast majority of passwords don't contain them anyway
                line = line.strip()
                computed_hash = hashfunction(line)
                new_line = computed_hash + ":" + line + "\n"
                if outfile != None:
                    fileHandler.write(new_line)
                else:
                    print(new_line,end="")
        if outfile != None:
            fileHandler.close()   
    
def main():    
    parser = argparse.ArgumentParser(description="Rainbowtool V1")
    misc = parser.add_argument_group('Miscellaneous')
    misc.add_argument("--listhashes",dest="listhashes",default=False,help="List supported hashing algorithms",action="store_true")

    cracking = parser.add_argument_group("Cracking")
    cracking.add_argument('--hash',dest='hashtocrack',default=False,help='The hash to crack')
    cracking.add_argument('--rainbowtable',dest='rainbowtable',help='The rainbow table to use to crack the hash',default=False)

    make_rainbow = parser.add_argument_group("Make Rainbow Tables")
    make_rainbow.add_argument("--wordlist",dest="wordlist",help="The wordlist to use for the rainbow table",default=False)
    make_rainbow.add_argument("--outfile",dest="outfile",help="The file to save the rainbow table to, defaults to stdout",default=None)
    make_rainbow.add_argument('--format',dest="format",help="The hash format to use",default=False)


    arguments = parser.parse_args()

    hashesObject = hashes()
    rainbowtoolObject = rainbowtool()
    functionDict = {"ntlm" : hashesObject.ntlm, "md5" : hashesObject.md5, "sha256" : hashesObject.sha256} # A dictionary of hashing functions
    if arguments.listhashes:
        hashesObject.list_hashes()
        exit(0)

    elif arguments.hashtocrack and arguments.rainbowtable:
        hashtocrack = arguments.hashtocrack
        rainbowtable = arguments.rainbowtable
        print("[+] Hash length : " + str(len(arguments.hashtocrack)))
        if isfile(rainbowtable):
            print("[+] Rainbow table exists")
        else:
            print("[-] Rainbow table does not exist; Try checking the file name")
            exit(1)
        rainbowtoolObject.crack_with_rainbowtable(hashtocrack,rainbowtable,format,verbose=True)
        
    elif arguments.wordlist and arguments.format:
        hash_function = functionDict[arguments.format]
        if not isfile(arguments.wordlist):
            print("[-] File does not exist")
            exit(1)
        rainbowtoolObject.make_rainbowtable(arguments.wordlist,hash_function,outfile=arguments.outfile)
        
            
    else:
        parser.print_help()
main()
    
        
    
    
