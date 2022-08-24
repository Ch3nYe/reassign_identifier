# How To Use

python generate_var_ast_courpus.py

## Json file format

```python3
with open("xxx.json","r") as f:
    function_info = json.load(f)
'''
function_info format:
    function_info["name"] = function_name
    function_info["start_ea"] = func.start_ea
    function_info["end_ea"] = func.end_ea
    function_info["var_addr_maps"] = var_addr_maps
    function_info["ast"] = new_graph.json_tree()
    function_info["raw_code"] = str(cfunc)
'''
```

## Thanks To

DIRE: Decompiled Identifier Renaming Engine: [CMUSTRUDEL/DIRE (github.com)](https://github.com/CMUSTRUDEL/DIRE)
