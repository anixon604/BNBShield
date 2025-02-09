import os

from dotenv import load_dotenv, find_dotenv
from eth_abi.abi import encode
from web3 import Web3, HTTPProvider

from utils import wait_for_receipt, load_abi


# ------------------------------------------------------------
# Helper: Sign EIP‑712 Attestation Payload
# ------------------------------------------------------------
def sign_attestation(
        w3: Web3,
        contract,
        record_id: int,
        submitter: str,
        agent: str,
        pointer: str,
        nonce_value: int,
        private_key: str,
) -> bytes:
    """
    Builds and signs the EIP‑712 attestation payload for a PEP record.

    The payload is equivalent to Solidity’s:

        keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,  // keccak256("PEPAttestationContract(uint256 id,address submitter,address shield,bytes32 pointer,uint256 nonce)")
                id,
                submitter,
                shield,
                keccak256(bytes(pointer)),
                nonce
            )
        );

    And the final digest is:

        keccak256( "\x19\x01" || DOMAIN_SEPARATOR || structHash )

    :param w3: Web3 instance.
    :param contract: The deployed contract instance.
    :param record_id: The PEP record id.
    :param submitter: The submitter’s address.
    :param agent: The shield’s address.
    :param pointer: The off-chain pointer (should match what was minted).
    :param nonce_value: A nonce for replay protection.
    :param private_key: The private key to sign with.
    :return: The 65-byte signature.
    """
    # Get the domain separator from the contract
    domain_separator = contract.functions.DOMAIN_SEPARATOR().call()  # bytes32

    # Compute the type hash exactly as in Solidity:
    # keccak256("PEPAttestationContract(uint256 id,address submitter,address agent,bytes32 pointer,uint256 nonce)")
    attestation_typehash = Web3.keccak(text="PEPAttestation(uint256 id,address submitter,address agent,bytes32 pointer,uint256 nonce)")

    # Compute hash of the pointer string as bytes32 (as done in Solidity)
    pointer_hash = Web3.keccak(text=pointer)

    # ABI-encode the attestation payload
    # Order must match: bytes32, uint256, address, address, bytes32, uint256
    encoded_data = encode(
        ['bytes32', 'uint256', 'address', 'address', 'bytes32', 'uint256'],
        [attestation_typehash, record_id, submitter, agent, pointer_hash, nonce_value]
    )
    struct_hash = Web3.keccak(encoded_data)

    # Compute EIP-712 digest: keccak256("\x19\x01" + DOMAIN_SEPARATOR + structHash)
    digest = Web3.keccak(b'\x19\x01' + domain_separator + struct_hash)

    # Sign the digest with the provided private key
    signed = w3.eth.account.unsafe_sign_hash(digest, private_key=private_key)
    return signed.signature


# ------------------------------------------------------------
# Function: mint_pep
# ------------------------------------------------------------
def mint_pep(w3: Web3, contract, pointer: str, wallet_address: str, private_key: str):
    """
    Calls the mintPEPRecord function of the contract.

    :param w3: Web3 instance.
    :param contract: The deployed PEPAttestation instance.
    :param pointer: The off-chain pointer (e.g. IPFS/Greenfield URI).
    :param wallet_address: The sender address.
    :param private_key: The sender’s private key.
    :return: A tuple (minted_record_id, tx_hash).
    """
   # w3.eth.get_transaction_count(account=w3.to_checksum_address(wallet_address))
    tx = contract.functions.mintPEPRecord(pointer).build_transaction({
        'chainId': 56,
        'gas':250000,
        'nonce': w3.eth.get_transaction_count(wallet_address)}
    )

    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"💎Minting PEP record with pointer '{pointer}' -  tx hash: https://bscscan.com/tx/{w3.to_hex(tx_hash)}")
    receipt = wait_for_receipt(w3, tx_hash)
    if receipt is None:
        raise Exception("Transaction receipt not found!")

    # For simplicity, we assume the new record id is (nextId - 1).
    minted_id = contract.functions.nextId().call() - 1
    print(f"Minted PEP record id: {minted_id}")
    return minted_id, w3.to_hex(tx_hash)


# ------------------------------------------------------------
# Function: attest_contract
# ------------------------------------------------------------
def attest_contract(
        w3: Web3,
        contract,
        record_id: int,
        pointer: str,
        nonce_value: int,
        submitter_private_key: str,
        agent_private_key: str,
):
    """
    Signs the attestation payload (for both submitter and shield) and calls attestRecord.

    :param w3: Web3 instance.
    :param contract: The deployed PEPAttestation instance.
    :param record_id: The id of the PEP record.
    :param pointer: The pointer that was used when minting.
    :param nonce_value: Nonce for replay protection (must match off-chain).
    :param submitter_private_key: Private key of the submitter.
    :param agent_private_key: Private key of the shield.
    :return: Transaction hash as hex string.
    """
    # Recover addresses from the private keys.
    submitter_address = w3.eth.account.from_key(submitter_private_key).address
    agent_address = w3.eth.account.from_key(agent_private_key).address

    # Sign the attestation payload with both keys.
    signature_submitter = sign_attestation(
        w3, contract, record_id, submitter_address, agent_address, pointer, nonce_value, submitter_private_key
    )
    print("✍️ Submitter Signed Attestation")

    signature_agent = sign_attestation(
        w3, contract, record_id, submitter_address, agent_address, pointer, nonce_value, agent_private_key
    )
    print("✍️ Agent Signed Attestation")

    # Build the transaction to call attestRecord.
    tx_sender = submitter_address
    tx = contract.functions.attestRecord(
        record_id,
        submitter_address,
        agent_address,
        pointer,
        nonce_value,
        signature_submitter,
        signature_agent
    ).build_transaction({
        'chainId': 56,
        'gas':250000,
        'nonce': w3.eth.get_transaction_count(submitter_address)}
    )

    signed_tx = w3.eth.account.sign_transaction(tx, submitter_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Attestation for record {record_id} submitted - tx hash: https://bscscan.com/tx/{w3.to_hex(tx_hash)}")
    receipt = wait_for_receipt(w3, tx_hash)
    if receipt is None:
        raise Exception("Attestation transaction receipt not found!")
    return w3.to_hex(tx_hash)


# ------------------------------------------------------------
# Example main: use mint_pep and attest_contract
# ------------------------------------------------------------
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

    # ----- Mint a new PEP record -----
    pointer = "https://testnet.greenfieldscan.com/bucket/0x0000000000000000000000000000000000000000000000000000000000005070"
    submitter_address = w3.eth.account.from_key(SUBMITTER_KEY).address
    minted_id, mint_tx = mint_pep(w3, pep_contract, pointer, submitter_address, SUBMITTER_KEY)
    print(f"Record minted with id {minted_id} in tx {mint_tx}")

    # ---- Attest the record -----
    # Use a nonce that matches the off-chain attestation (must be agreed upon by both parties)
    nonce_value = 10
    attest_tx = attest_contract(
        w3,
        pep_contract,
        minted_id,
        pointer,
        nonce_value,
        SUBMITTER_KEY,
        AGENT_KEY
    )
    print(f"✅ Attestation Complete.")
    print(f"💛 BNB smart chain transaction hash: {attest_tx}")