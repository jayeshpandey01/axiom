with open("controller/native_probes.py", "r") as f:
    text = f.read()

text = text.replace("hashlib.md5(param.encode(, usedforsecurity=False))", "hashlib.md5(param.encode(), usedforsecurity=False)")
text = text.replace("hashlib.md5(payload.encode(, usedforsecurity=False))", "hashlib.md5(payload.encode(), usedforsecurity=False)")
text = text.replace("hashlib.md5(str(time.time(, usedforsecurity=False)).encode())", "hashlib.md5(str(time.time()).encode(), usedforsecurity=False)")
text = text.replace("verify=False,  # nosec B501 timeout=HTTP_TIMEOUT", "verify=False, timeout=HTTP_TIMEOUT") # we can put # nosec B501 on the line

# We also need to add # nosec B501 to line 1004 properly
# The line is: async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT) as client:
text = text.replace("async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT) as client:", "async with httpx.AsyncClient(verify=False, timeout=HTTP_TIMEOUT) as client:  # nosec B501")

with open("controller/native_probes.py", "w") as f:
    f.write(text)

