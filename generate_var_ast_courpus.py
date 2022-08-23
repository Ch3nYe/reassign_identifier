#!/bin/python3

'''
@usage: python generate_var_ast_courpus.py
@disc: dump data from binary by ida pro.
requirements:
    1. binary file name should end with the same suffix (BIN_SUFFIX), e.g. .so
    2. binary file need to be stripped correctly and save to BINARY_FILE.stripped
results:
    1. collect all variable address map, save to BINARY_FILE.varmap.pickle
    2. collect all functions info, save to BINARY_FILE.json
    3. and the idb file will saved into BINARY_FILE.idb or .i64
'''

from multiprocessing import Process, Queue, cpu_count
import os
import glob


collect_var_idapython_path = "D:/PythonProject/reassign_identifier/collect_var_idapython.py"
dump_info_idapython_path = "D:/PythonProject/reassign_identifier/dump_info_idapython.py"
binary_path = "D:/PythonProject/reassign_identifier/examples"
os.environ["LOG_FILE"] = "D:/PythonProject/reassign_identifier/log.txt"
BIN_SUFFIX = "*.so"

def single_test(binary_file, IDA = "ida64"):
    '''
    process a binary for test and debug, use -L to save ida loggings
    '''
    print('[-] process: {}'.format(binary_file))
    os.system(f"{IDA} -A -L{binary_file}.idalog -S{collect_var_idapython_path} {binary_file}")
    os.system(f"strip {binary_file} -o {binary_file}.stripped")
    os.system(f"{IDA} -A -L{binary_file}.stripped.idalog -S{dump_info_idapython_path} {binary_file}.stripped")

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

        os.system(f"{IDA} -A -S{collect_var_idapython_path} {binary_file}")
        # os.system(f"strip {binary_file} -o {binary_file}.stripped")
        os.system(f"{IDA} -A -S{dump_info_idapython_path} {binary_file}.stripped")

def multiprocess_process(binary_file_queue, thread_id):
    count = 0
    while not binary_file_queue.empty():
        count+=1
        binary_file = binary_file_queue.get()

        IDA = "ida" if "_32_" in binary_file else "ida64"
        print(f'[t{thread_id}] process {count}th: {binary_file}')

        os.system(f"{IDA} -A -S{collect_var_idapython_path} {binary_file}")
        # os.system(f"strip {binary_file} -o {binary_file}.stripped")
        os.system(f"{IDA} -A -S{dump_info_idapython_path} {binary_file}.stripped")
        
        
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

    threads = 4 # cpu_count()//2
    processes = [Process(target=multiprocess_process, args=(queue, i)) for i in range(threads)]
    for p in processes:
        p.start()
    for p in processes:
        p.join()


if __name__ == '__main__':
    # single_test("D:/PythonProject/reassign_identifier/examples/openssl-openssl-3.0.0_clang-11.0_x86_64_O0_libcrypto.so", IDA="ida64")

    # main()

    multiprocess_main()
