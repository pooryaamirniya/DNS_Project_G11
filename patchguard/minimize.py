"""Deterministic byte-level delta debugging, using the precise sanitizer finding as predicate."""
from .runner import run
from .detection import detect, signature


def ddmin(data, test, budget=250):
    chunks = 2
    attempts = 0
    while len(data) > 1 and attempts < budget:
        stride = max(1, (len(data) + chunks - 1) // chunks)
        reduced = False
        for i in range(0, len(data), stride):
            candidate = data[:i] + data[i+stride:]
            attempts += 1
            if candidate and test(candidate):
                data = candidate
                chunks = max(2, chunks-1)
                reduced = True
                break
            if attempts >= budget:
                break
        if not reduced:
            if chunks >= len(data):
                break
            chunks = min(len(data), chunks*2)
    return data, attempts


def minimize_crash(binary, data, reference, budget=250, mode="stdin"):
    key = signature(reference)
    if key is None:
        return data, 0
    def same(candidate):
        result = detect(run(binary, candidate, mode=mode))
        return signature(result) == key
    return ddmin(data, same, budget=budget)
