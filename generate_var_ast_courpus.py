#!/bin/python3

'''
@usage: python generate_var_ast_courpus.py
@disc: dump data from binary by ida pro.
requirements:
    1. binary file name should end with the same suffix (BIN_SUFFIX), e.g. .so
    2. binary file name should contain "_32_" or "_64_" to indicate file arch to choose ida(64)
    3. binary file need to be stripped correctly and save to BINARY_FILE.stripped
results:
    1. collect all variable address map, save to BINARY_FILE.varmap.pickle
    2. collect all functions info, save to BINARY_FILE.json
    3. and the idb file will saved into BINARY_FILE.idb or .i64
'''

from multiprocessing import Process, Queue, cpu_count
import os
import glob
import subprocess


collect_var_idapython_path = "D:/PythonProject/reassign_identifier/collect_var_idapython.py"
dump_info_idapython_path = "D:/PythonProject/reassign_identifier/dump_info_idapython.py"
binary_path = "D:/PythonProject/reassign_identifier/examples"
os.environ["LOG_FILE"] = "D:/PythonProject/reassign_identifier/idalog.txt"
error_list_file = "D:/PythonProject/reassign_identifier/bianry_unanalyzable_list.txt"
BIN_SUFFIX = "*.elf"
BIN_TIMEOUT = 1800 # set timeout for each binary


def single_test(binary_file, IDA = "ida64"):
    '''
    process a binary for test and debug, use -L to save ida loggings
    '''
    print('[-] process: {}'.format(binary_file))
    cmd1 = f"{IDA} -A -L{binary_file}.idalog -S{collect_var_idapython_path} {binary_file}"
    cmd2 = f"{IDA} -A -L{binary_file}.stripped.idalog -S{dump_info_idapython_path} {binary_file}.stripped"
    try:
        subprocess.check_call(cmd1, shell=True, timeout=BIN_TIMEOUT)
        # os.system(f"strip {binary_file} -o {binary_file}.stripped") # strip may not support a file arch
        subprocess.check_call(cmd2, shell=True, timeout=BIN_TIMEOUT)
    except Exception as e:
        print(e)
        if type(e) == subprocess.TimeoutExpired:
            print("[!] timeout:", binary_file)
        os.system(f"echo {binary_file} >> {error_list_file}")


def main():
    '''
    process binaries from binary_path with single process
    '''
    for binary_file in glob.glob(os.path.join(binary_path, BIN_SUFFIX)):
        if os.path.exists(binary_file+".stripped.i64") or \
            os.path.exists(binary_file+".stripped.idb"):
            continue
        
        IDA = "ida" if "_32_" in binary_file else "ida64"
        binary_file = os.path.join(binary_path, binary_file)
        
        print('[-] process: {}'.format(binary_file))
        cmd1 = f"{IDA} -A -S{collect_var_idapython_path} {binary_file}"
        cmd2 = f"{IDA} -A -S{dump_info_idapython_path} {binary_file}.stripped"
        try:
            subprocess.check_call(cmd1, shell=True, timeout=BIN_TIMEOUT)
            # os.system(f"strip {binary_file} -o {binary_file}.stripped") # strip may not support a file arch
            subprocess.check_call(cmd2, shell=True, timeout=BIN_TIMEOUT)
        except Exception as e:
            print(e)
            if type(e) == subprocess.TimeoutExpired:
                print("[!] timeout:", binary_file)
            os.system(f"echo {binary_file} >> {error_list_file}")


def multiprocess_process(binary_file_queue, thread_id):
    count = 0
    while not binary_file_queue.empty():
        count+=1
        binary_file = binary_file_queue.get()

        IDA = "ida" if "_32_" in binary_file else "ida64"
        print(f'[t{thread_id}] process {count}th: {binary_file}')

        cmd1 = f"{IDA} -A -S{collect_var_idapython_path} {binary_file}"
        cmd2 = f"{IDA} -A -S{dump_info_idapython_path} {binary_file}.stripped"
        try:
            subprocess.check_call(cmd1, shell=True, timeout=BIN_TIMEOUT)
            # os.system(f"strip {binary_file} -o {binary_file}.stripped") # strip may not support a file arch
            subprocess.check_call(cmd2, shell=True, timeout=BIN_TIMEOUT)
        except Exception as e:
            print(f"[t{thread_id}]", e)
            if type(e) == subprocess.TimeoutExpired:
                print(f"[t{thread_id}] timeout: {binary_file}")
            os.system(f"echo {binary_file} >> {error_list_file}")

        
def multiprocess_main():
    '''
    process binaries from binary_path with multi process
    '''
    queue = Queue()
    for binary_file in glob.glob(os.path.join(binary_path, BIN_SUFFIX)):
        if os.path.exists(binary_file+".stripped.i64") or \
            os.path.exists(binary_file+".stripped.idb"):
            continue
        queue.put(os.path.join(binary_path, binary_file))

    try:
        threads = 4 # cpu_count()//2
        processes = [Process(target=multiprocess_process, args=(queue, i)) for i in range(threads)]
        for p in processes:
            p.start()
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        for p in processes:
            p.terminate()
    

if __name__ == '__main__':
    # single_test("D:/PythonProject/reassign_identifier/examples/coreutils_8.29_gcc-7.3.0_x86_32_O3_cut.elf", IDA="ida")

    # main()

    multiprocess_main()
