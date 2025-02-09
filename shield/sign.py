import os

from dotenv import load_dotenv, find_dotenv
from web3 import Web3, HTTPProvider

from shield.agent_executor import mint_pep, sign_attestation
from utils import load_abi

if __name__ == "__main__":
    
    env_path = find_dotenv()
    load_dotenv(env_path)
    from web3.middleware import ExtraDataToPOAMiddleware

    pep_address = os.getenv("PEP_CONTRACT_ADDRESS")
    bsc_web3_url = os.getenv("BSC_WEB3_URL")

    SUBMITTER_KEY = os.getenv("SUBMITTER_PRIVATE_KEY")
    AGENT_KEY = os.getenv("AGENT_PRIVATE_KEY")

    if not all([pep_address, bsc_web3_url, SUBMITTER_KEY, AGENT_KEY]):
        raise Exception("Please set PEP_CONTRACT_ADDRESS, BSC_WEB3_URL, SUBMITTER_PRIVATE_KEY, and AGENT_PRIVATE_KEY in your environment.")

    w3 = Web3(HTTPProvider(bsc_web3_url, request_kwargs={'timeout': 6}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    pep_abi = load_abi("./pep_attestation.json")
    pep_contract = w3.eth.contract(address=pep_address, abi=pep_abi)

    # Sign the attestation payload with both keys.
    # signature_submitter = sign_attestation(
    #     w3, contract, record_id, submitter_address, agent_address, pointer, nonce_value, submitter_private_key
    # )
    # signature_agent = sign_attestation(
    #     w3, contract, record_id, submitter_address, agent_address, pointer, nonce_value, agent_private_key
    # )