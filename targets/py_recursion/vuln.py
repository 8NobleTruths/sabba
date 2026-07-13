"""A parser that recurses once per input byte with no depth limit. Long input drives the
recursion past the interpreter limit and raises RecursionError, an input-driven stack
exhaustion denial of service (CWE-674). Self-contained so a fuzzer can prove it with no
network or external state, the Python analog of the cJSON stack-exhaustion bug the C oracle
already proves.
"""


def deep(s, i=0):
    if i >= len(s):
        return i
    return deep(s, i + 1)


def run(data):
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("latin1")
    return deep(data)
