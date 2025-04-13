import time
import logging
from typing import List
from block import Block

class BlockchainEngine:
    def __init__(self, difficulty: int = 5) -> None:
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self.create_genesis_block()

    def create_genesis_block(self) -> None:
        logging.info("Mining Genesis block...")

        genesis_block = Block(data="Genesis Block")
        self.mine_block(genesis_block)
        self.chain.append(genesis_block)

        logging.info("Genesis block added for chain.")

    def mine_block(self, block: Block) -> None:
        prefix = "0" * self.difficulty
        nonce = 0
        start_time = time.time()

        while True:
            computed_hash = block.compute_hash(nonce)
            if computed_hash.startswith(prefix):
                block.nonce = nonce
                block.hash = computed_hash
                break
            nonce += 1

        elapsed_time = time.time() - start_time

        logging.info(f"Block '{block.data}' mining for {elapsed_time:.2f} seconds, nonce={block.nonce}")

    def add_block(self, data) -> None:
        prev_hash = self.chain[-1].hash if self.chain else ""
        new_block = Block(data=data, prev_hash=prev_hash)

        self.mine_block(new_block)
        self.chain.append(new_block)

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            if current.prev_hash != prev.hash:
                return False
            if current.hash != current.compute_hash(current.nonce):
                return False
            
        return True

    def __str__(self) -> str:
        chain_str = ""
        for i, block in enumerate(self.chain):
            chain_str += f"Block {i}:\n  Data: {block.data}\n  Prev hash: {block.prev_hash}\n  Nonce: {block.nonce}\n  Hash: {block.hash}\n\n"

        return chain_str
