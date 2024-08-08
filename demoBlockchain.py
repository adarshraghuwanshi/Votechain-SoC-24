import hashlib
import time
import requests

class Block:
    def __init__(self, index, timestamp, vote_info, proof, previous_hash):
        """ This initializes a block with index, timestamp, vote information, proof, and previous hash."""
        pass

    def compute_hash(self):
        """ This function computes the hash of the block."""
        pass


class Blockchain:
    def __init__(self):
        """ This initializes the blockchain with the genesis block and other necessary inputs."""
        pass

    def create_genesis_block(self):
        """ This function creates and returns the genesis block."""
        pass

    def get_latest_block(self):
        """ This function returns the latest block in the chain."""
        pass

    def add_block(self, new_block):
        """ This function adds a new block to the chain after setting its previous hash and computing its hash."""
        pass

    def validate_chain(self, chain):
        """ This function validates the entire blockchain by checking the hashes and proofs of work."""
        pass

    def update_chain(self):
        """ This updates the blockchain with the longest valid chain from neighbouring nodes."""
        pass

    def proof_of_work(self, previous_proof):
        """ This function generates a valid proof of work for a given previous proof."""
        pass

    def create_block(self, previous_hash, proof):
        """ This creates a new block with the given proof and previous hash."""
        pass

    def create_vote(self, voter_name, unique_ID, voted_for):
        """ This adds a new vote to the current vote information."""
        pass

    def hash(self, block):
        """ This function generates the SHA-256 hash of a given block."""
        pass

    def last_block(self):
        """ This function returns the last block in the current chain."""
        pass


