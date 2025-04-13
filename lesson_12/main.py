import logging
from blockchain_engine import BlockchainEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main() -> None:
    values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]

    blockchain = BlockchainEngine(difficulty=5)
    
    for value in values:
        blockchain.add_block(data=value)

    print("Final blockchain:\n")
    print(blockchain)
    
    if blockchain.is_valid():
        logging.info("Blockchain valid!")
    else:
        logging.error("Blockchain invalid!")

if __name__ == "__main__":
    main()