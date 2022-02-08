#!/usr/bin/python3


#---------------------------------------------#
# Dependencies: 0 (Standard Python3 Library)
# License: GPL3
# Author: trevalkov
#---------------------------------------------#
import threading, hashlib, time, sys, os 


#---------------------------------------------#
# switch to kill threads once hash is cracked
# with func call
# reads the configs passed, splits the wordlist
# into multiple lists according to the number
# of threads given and start a pool of threads,
# then we use the switch to kill all if we one
# finds the right hash      
#---------------------------------------------#
flag = False


def kill_threads():
    global flag
    flag = True
    return 0


def run_threads(configs, timer=True):
    global flag
    
    if timer:
        start = time.time()
    
    hash_input = configs["hash_input"]
    hash_type = configs["hash_type"]
    wordlist_location = configs["wordlist_location"]
    n_threads = configs["n_threads"]
    lists = split_list(wordlist_location, n_threads)
  
    threads = list()
    for i in range(1, n_threads+1):
        threads.append(threading.Thread(target=hash_cracker, args=(hash_input, hash_type, lists[i-1])))
        threads[i-1].start()
        threads[i-1].join()
   
    if not flag:
        print("no matches found")
    cmd = "rm -rf /tmp/hc_wordlists"
    os.system(cmd)

    if timer:
        finish = time.time()
        time_elapsed = finish - start
        print("%.2f seconds" % time_elapsed)
    exit(0)


def split_list(wordlist_location, n_threads):
    lists = list()
    with open(wordlist_location, "r") as wl:
        lines = wl.read().splitlines()
        n_lines = len(lines)
        size_l = n_lines // n_threads

        hc_wordlists = "/tmp/hc_wordlists"
        if os.path.exists(hc_wordlists):
            os.system(f"rm -r {hc_wordlists}")
        os.mkdir(hc_wordlists)
        
        for i in range(1, n_threads+1):
            new_list = f"{hc_wordlists}/wordlist{i}.tmp"
            lists.append(new_list)
            if i == n_threads:
                with open(new_list, 'w') as wls:
                    for line in lines[(i-1)*size_l:]:
                        wls.write(f"{line}\n")
            else:
                with open(new_list, 'w') as wls:
                    for line in lines[(i-1)*size_l:i*size_l]:
                        wls.write(f"{line}\n")
    return lists


#---------------------------------------------#
# get arguments to call
#---------------------------------------------#
def setup():
    configs = dict()
    if len(sys.argv) != 5:
        sys.stderr.write("Usage ./hash_cracker.py <hash_input> <hash_type> <wordlist_location> <n_threads>\n")
        exit(1)
    else:
        configs["hash_input"] = sys.argv[1]
        configs["hash_type"] = sys.argv[2]
        configs["wordlist_location"] = sys.argv[3]
        try:
            configs["n_threads"] = int(sys.argv[4])
        except ValueError:
            sys.stderr.write(f"[!] ErrorValue '{sys.argv[4]}' must be of type int\n")
            exit(1)
    return configs



#---------------------------------------------#
# cracking logic, reads hash type from configs
# and selects the right function to crack these
# hash, I have left this conditional to be
# run by every thread in the possibility of
# trying to detect an hashtype which could be
# multithreaded and managed with a switch
#---------------------------------------------#
def crack_md5(hash_input, wordlist_location):
    global flag
    with open(wordlist_location, 'r') as file:
        for line in file.readlines():
            if flag:
                exit(0)
            hash_ob = hashlib.md5(line.strip().encode())
            hashed_pass = hash_ob.hexdigest()
            if hashed_pass == hash_input:
                print(line.strip())
                kill_threads()
    return 0


def crack_sha256(hash_input, wordlist_location):
    global flag
    with open(wordlist_location, 'r') as file:
        for line in file.readlines():
            if flag:
                exit(0)
            hash_ob = hashlib.sha256(line.strip().encode())
            hashed_pass = hash_ob.hexdigest()
            if hashed_pass == hash_input:
                print(line.strip())
                kill_threads()
    return 0


def hash_cracker(hash_input, hash_type, wordlist_location):
    if hash_type == "sha256":
        crack_sha256(hash_input, wordlist_location)
    else:
        crack_md5(hash_input, wordlist_location)
    return 0


#---------------------------------------------#
#---------------------------------------------#
if __name__ == '__main__':
    configs = setup()
    run_threads(configs)


