import asyncio
import argparse
import logging

import alice
import bob
from models.constants import Constants

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def parse_args():
    parser = argparse.ArgumentParser(description="Chat application")
    parser.add_argument("role", choices=[Constants.ALICE, Constants.BOB], help=f"Role to start: {Constants.ALICE} or {Constants.BOB}")
    parser.add_argument("--debug_mode", action="store_true", help="Enable debug mode")
    return parser.parse_args()

def main():
    args = parse_args()
    
    if args.debug_mode:
        print("Debug mode enabled")
    
    if args.role == Constants.ALICE:
        print("Starting Alice...")
        asyncio.run(alice.init_connection_wrapper(args.debug_mode))
    elif args.role == Constants.BOB:
        print("Starting Bob...")
        asyncio.run(bob.init_connection_wrapper(args.debug_mode))

if __name__ == "__main__":
    main()