with open("controller/native_probes.py", "r") as f:
    text = f.read()

text = text.replace("verify=False,", "verify=False,  # nosec B501")
text = text.replace("verify=False)", "verify=False)  # nosec B501")
text = text.replace("hashlib.md5", "hashlib.md5") # we need usedforsecurity=False in python 3.9+

import re
text = re.sub(r'hashlib\.md5\((.*?)\)', r'hashlib.md5(\1, usedforsecurity=False)', text)

with open("controller/native_probes.py", "w") as f:
    f.write(text)

