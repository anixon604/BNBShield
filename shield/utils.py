import os
import time

import ujson
from web3.exceptions import TransactionNotFound


def wait_for_receipt(w3, tx_hash, retries=30, delay=5):
    for _ in range(retries):
        print('🕙Waiting for receipt... for tx:', tx_hash.hex())
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            if receipt:
                return receipt
            else:
                raise TransactionNotFound('Transaction not found')
        except TransactionNotFound:
            time.sleep(delay)
    return None

class ABICache:
    filename_to_abi: dict[str, list] = {}


def load_abi(filename: str) -> list:
    assert filename
    if abi := ABICache.filename_to_abi.get(filename, None):
        return abi
    root_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    folder = os.path.join(root_directory, "abi")
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"The ABI file {filepath} does not exist.")
    with open(filepath, "r", encoding="utf-8") as f:
        res = ujson.load(f)
        ABICache.filename_to_abi[filename] = res
        return res