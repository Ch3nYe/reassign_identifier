#!/usr/bin/python3

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
import psutil
import subprocess


collect_var_idapython_path = "D:/PythonProject/reassign_identifier/collect_var_idapython.py"
dump_info_idapython_path = "D:/PythonProject/reassign_identifier/dump_info_idapython.py"
binary_path = "D:/PythonProject/reassign_identifier/examples2"
os.environ["LOG_FILE"] = "D:/PythonProject/reassign_identifier/828idalog.txt"
error_list_file = "D:/PythonProject/reassign_identifier/828binary_unanalyzable_list.txt"
BIN_SUFFIX = "*.elf"
BIN_TIMEOUT = 3600*3 # set timeout for each binary


def kill_pstree(pid):
    if pid:
        try:
            children = psutil.Process(pid).children(recursive=True)
            for child in children:
                child.terminate()
            _, still_alive = psutil.wait_procs(children, timeout=5)
            for child in still_alive:
                child.kill()
        except:
            pass

def single_test(binary_file, IDA = "ida64"):
    '''
    process a binary for test and debug, use -L to save ida loggings
    '''
    print('[-] process: {}'.format(binary_file))
    cmd1 = f"{IDA} -A -L{binary_file}.idalog -S{collect_var_idapython_path} {binary_file}"
    cmd2 = f"{IDA} -A -L{binary_file}.stripped.idalog -S{dump_info_idapython_path} {binary_file}.stripped"
    p1_id, p2_id = None, None
    try:
        p1 = subprocess.Popen(cmd1, shell=True)
        p1_id = p1.pid
        assert 0 == p1.wait(timeout=BIN_TIMEOUT), "[!] decompile returned non-zero exit"
        # os.system(f"strip {binary_file} -o {binary_file}.stripped") # strip may not support a file arch
        p2 = subprocess.Popen(cmd2, shell=True)
        p2_id = p2.pid
        assert 0 == p2.wait(timeout=BIN_TIMEOUT), "[!] decompile returned non-zero exit"
    except Exception as e:
        kill_pstree(p1_id)
        kill_pstree(p2_id)
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
        p1_id, p2_id = None, None
        try:
            p1 = subprocess.Popen(cmd1, shell=True)
            p1_id = p1.pid
            assert 0 == p1.wait(timeout=BIN_TIMEOUT), "[!] decompile returned non-zero exit"
            # os.system(f"strip {binary_file} -o {binary_file}.stripped") # strip may not support a file arch
            p2 = subprocess.Popen(cmd2, shell=True)
            p2_id = p2.pid
            assert 0 == p2.wait(timeout=BIN_TIMEOUT), "[!] decompile returned non-zero exit"
        except Exception as e:
            kill_pstree(p1_id)
            kill_pstree(p2_id)
            print(e)
            if type(e) == subprocess.TimeoutExpired:
                print("[!] timeout:", binary_file)
            os.system(f"echo {binary_file} >> {error_list_file}")


def multiprocess_process(binary_file_queue, thread_id):
    count = 0
    while not binary_file_queue.empty():
        count+=1
        binary_file = binary_file_queue.get()
        print(f'[t{thread_id}] process {count}th: {binary_file}, remain {binary_file_queue.qsize()}')
        IDA = "ida" if "_32_" in binary_file else "ida64"

        cmd1 = f"{IDA} -A -S{collect_var_idapython_path} {binary_file}"
        cmd2 = f"{IDA} -A -S{dump_info_idapython_path} {binary_file}.stripped"
        p1_id, p2_id = None, None
        try:
            p1 = subprocess.Popen(cmd1, shell=True)
            p1_id = p1.pid
            assert 0 == p1.wait(timeout=BIN_TIMEOUT), "decompile returned non-zero exit"
            # os.system(f"strip {binary_file} -o {binary_file}.stripped") # strip may not support a file arch
            p2 = subprocess.Popen(cmd2, shell=True)
            p2_id = p2.pid
            assert 0 == p2.wait(timeout=BIN_TIMEOUT), "decompile returned non-zero exit"
        except Exception as e:
            kill_pstree(p1_id)
            kill_pstree(p2_id)
            print(f"[t{thread_id}] {binary_file}", e)
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
        threads = cpu_count()//2
        processes = [Process(target=multiprocess_process, args=(queue, i)) for i in range(threads)]
        for p in processes:
            p.start()
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        for p in processes:
            p.terminate()
    

if __name__ == '__main__':
    # single_test("D:/PythonProject/reassign_identifier/examples/openssl-openssl-3.0.0_gcc-8.2.0_arm_32_O0_libssl.so.elf", IDA="ida")

    # main()

    multiprocess_main()
