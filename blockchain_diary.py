import hashlib
import time
import os
import json
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Constants
PASSWORD_FILE = "password.hash"
ENCRYPTION_KEY_FILE = "encryption.key"


# Function to generate a new encryption key
def generate_encryption_key():
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key


# Function to load the encryption key from file
def load_encryption_key():
    if not os.path.exists(ENCRYPTION_KEY_FILE):
        return generate_encryption_key()
    with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
        return key_file.read()


# Load encryption key for diary entry encryption
encryption_key = load_encryption_key()
fernet = Fernet(encryption_key)


# Functions for password handling
def set_password():
    password = input(Fore.YELLOW + "Set your password: ").encode()
    confirm_password = input(Fore.YELLOW + "Confirm your password: ").encode()

    if password != confirm_password:
        print(Fore.RED + "Passwords do not match. Try again.")
        return False

    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    with open(PASSWORD_FILE, "wb") as f:
        f.write(hashed)

    print(Fore.GREEN + "Password set successfully!")
    return True


def verify_password():
    if not os.path.exists(PASSWORD_FILE):
        print(Fore.RED + "No password found. Please set one first.")
        set_password()

    password = input(Fore.YELLOW + "Enter your password to proceed: ").encode()

    with open(PASSWORD_FILE, "rb") as f:
        stored_password = f.read()

    if bcrypt.checkpw(password, stored_password):
        print(Fore.GREEN + "Access granted.")
        return True
    else:
        print(Fore.RED + "Incorrect password. Access denied.")
        return False


# Encrypt diary entries
def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()


# Decrypt diary entries
def decrypt_data(data):
    return fernet.decrypt(data.encode()).decode()


class Block:
    def __init__(
        self,
        index,
        timestamp,
        diary_entries,
        previous_hash="",
        software_version="1.0.0",
        difficulty_target=4,
    ):
        self.index = index
        self.timestamp = timestamp
        self.diary_entries = [
            encrypt_data(entry) for entry in diary_entries
        ]  # Encrypt entries
        self.entry_hashes = [
            hashlib.sha256(entry.encode("utf-8")).hexdigest() for entry in diary_entries
        ]  # Store hashes
        self.previous_hash = previous_hash
        self.software_version = software_version
        self.difficulty_target = difficulty_target
        self.merkle_root = (
            self.calculate_merkle_root()
        )  # Calculate Merkle root for the block
        self.nonce = 0  # Initialize nonce before calculating hash
        self.hash = self.calculate_hash()  # Now you can safely calculate the hash

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.previous_hash}{self.software_version}{self.difficulty_target}{self.merkle_root}{self.nonce}"
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def mine_block(self):
        while self.hash[: self.difficulty_target] != "0" * self.difficulty_target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(Fore.GREEN + f"Block mined: {self.hash}")

    def calculate_merkle_root(self):
        hashed_entries = [
            hashlib.sha256(entry.encode("utf-8")).hexdigest()
            for entry in self.diary_entries
        ]

        while len(hashed_entries) > 1:
            temp_hashes = []
            for i in range(0, len(hashed_entries), 2):
                if i + 1 < len(hashed_entries):
                    combined_hash = hashlib.sha256(
                        (hashed_entries[i] + hashed_entries[i + 1]).encode("utf-8")
                    ).hexdigest()
                else:
                    combined_hash = hashlib.sha256(
                        (hashed_entries[i] + hashed_entries[i]).encode("utf-8")
                    ).hexdigest()
                temp_hashes.append(combined_hash)
            hashed_entries = temp_hashes

        return hashed_entries[0]

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "diary_entries": self.diary_entries,
            "entry_hashes": self.entry_hashes,  # Store hashes in dictionary
            "previous_hash": self.previous_hash,
            "software_version": self.software_version,
            "difficulty_target": self.difficulty_target,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, block_dict):
        software_version = block_dict.get("software_version", "1.0.0")
        difficulty_target = block_dict.get("difficulty_target", 4)
        diary_entries = [decrypt_data(entry) for entry in block_dict["diary_entries"]]
        block = cls(
            block_dict["index"],
            block_dict["timestamp"],
            diary_entries,
            block_dict["previous_hash"],
            software_version,
            difficulty_target,
        )
        block.entry_hashes = block_dict.get("entry_hashes", [])  # Load stored hashes
        block.merkle_root = block_dict.get("merkle_root", "")
        block.nonce = block_dict.get("nonce", 0)
        block.hash = block_dict.get("hash", "")
        return block


class Blockchain:
    def __init__(self):
        self.software_version = "1.2.0"  # Update the software version here
        self.difficulty_target = 4  # Difficulty of mining (leading zeros)
        self.chain = [self.create_genesis_block()]  # Create genesis block
        self.pending_entries = []
        self.load_blockchain()  # Load blockchain data from file
        self.validate_chain()  # Validate the blockchain when the app starts

    def create_genesis_block(self):
        """
        Creates the first block (genesis block) of the blockchain.
        """
        return Block(
            0,
            "2024-11-16",
            ["Genesis Entry - Start of your digital diary."],
            "0",
            software_version=self.software_version,
            difficulty_target=self.difficulty_target,
        )

    def get_latest_block(self):
        """
        Returns the latest block in the blockchain.
        """
        return self.chain[-1]

    def add_entry(self, diary_entries):
        """
        Adds a new diary entry by creating a new block and appending it to the blockchain.
        """
        new_block = Block(
            len(self.chain),
            time.strftime("%Y-%m-%d %H:%M:%S"),
            diary_entries,
            self.get_latest_block().hash,
            software_version=self.software_version,
            difficulty_target=self.difficulty_target,
        )
        new_block.mine_block()
        self.chain.append(new_block)
        self.save_blockchain()  # Save blockchain to file

    def is_valid(self):
        """
        Validates the blockchain by checking the hash consistency, links between blocks, and Merkle root.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            # Check if the block's hash is valid
            if current_block.hash != current_block.calculate_hash():
                print(f"Block #{current_block.index} has an invalid hash!")
                return False
            # Check if the previous block's hash is correct
            if current_block.previous_hash != previous_block.hash:
                print(f"Block #{current_block.index} has an invalid previous hash!")
                return False
            # Check if the Merkle root is valid
            if current_block.merkle_root != current_block.calculate_merkle_root():
                print(f"Block #{current_block.index} has an invalid Merkle root!")
                return False
        return True

    def validate_chain(self):
        """
        Validates the blockchain upon startup, including Merkle root validation.
        """
        if not self.is_valid():
            print(Fore.RED + "Blockchain is invalid! Data may be tampered with.")
        else:
            print(Fore.GREEN + "Blockchain is valid.")

    def display_blockchain(self):
        """
        Prints the details of the blockchain in a readable format.
        """
        os.system("cls" if os.name == "nt" else "clear")  # Clear the terminal screen
        print(Fore.YELLOW + Style.BRIGHT + "=== Blockchain Digital Diary ===\n")

        for block in self.chain:
            print(Fore.CYAN + f"Block #{block.index}")
            print(f"{Fore.WHITE}Timestamp: {block.timestamp}")
            print(f"{Fore.GREEN}Diary Entries: {block.diary_entries}")
            print(f"{Fore.MAGENTA}Hash: {block.hash}")
            print(f"{Fore.YELLOW}Previous Hash: {block.previous_hash}")
            print(f"{Fore.BLUE}Software Version: {block.software_version}")
            print(f"{Fore.RED}Difficulty Target: {block.difficulty_target}")
            print(f"{Fore.CYAN}Merkle Root: {block.merkle_root}")
            print(f"{Fore.GREEN}Nonce: {block.nonce}")
            print(Fore.LIGHTBLACK_EX + "-" * 40)

    def display_diary_entries(self):
        """
        Prints the diary entries from the blockchain, separated by block numbers.
        Each diary entry will be decrypted before being displayed.
        """
        os.system("cls" if os.name == "nt" else "clear")  # Clear the terminal screen
        print(Fore.YELLOW + Style.BRIGHT + "=== Blockchain Digital Diary ===\n")

        print(Fore.CYAN + "Diary Entries by Block:")

        # Loop through all blocks and print their decrypted diary entries
        for block in self.chain:
            print(Fore.CYAN + f"\nBlock #{block.index} - {block.timestamp}")
            if block.diary_entries:
                for entry in block.diary_entries:
                    decrypted_entry = decrypt_data(entry)
                    print(f"  {Fore.WHITE}- {decrypted_entry}")
            else:
                print(f"{Fore.RED}  No entries in this block.")

        print(Fore.YELLOW + "\nEnd of Diary Entries.")

    def save_blockchain(self):
        """Save the blockchain to a file (blockchain.txt)"""
        blockchain_data = [block.to_dict() for block in self.chain]
        with open("blockchain.txt", "w") as file:
            json.dump(blockchain_data, file, indent=4)

    def load_blockchain(self):
        """Load the blockchain from a file (blockchain.txt)"""
        if os.path.exists("blockchain.txt"):
            with open("blockchain.txt", "r") as file:
                blockchain_data = json.load(file)
                self.chain = [Block.from_dict(block) for block in blockchain_data]

    def validate_entire_blockchain(self):
        """
        Validates the entire blockchain by checking the hash consistency, links between all blocks,
        and the validity of the Merkle root for each block.
        Additionally, validate that the diary entries can be decrypted properly (i.e., no tampering).
        Prints detailed information about any invalid blocks.
        """
        invalid_blocks = []

        # Iterate over the blockchain, starting from the second block (index 1)
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Validate the current block's hash
            if current_block.hash != current_block.calculate_hash():
                invalid_blocks.append(
                    {
                        "index": current_block.index,
                        "error": f"Hash mismatch for block #{current_block.index}. Expected: {current_block.calculate_hash()}, Found: {current_block.hash}",
                    }
                )

            # Validate the link between the current block and the previous block
            if current_block.previous_hash != previous_block.hash:
                invalid_blocks.append(
                    {
                        "index": current_block.index,
                        "error": f"Previous hash mismatch for block #{current_block.index}. Expected: {previous_block.hash}, Found: {current_block.previous_hash}",
                    }
                )

            # Validate the Merkle root of the current block
            if current_block.merkle_root != current_block.calculate_merkle_root():
                invalid_blocks.append(
                    {
                        "index": current_block.index,
                        "error": f"Merkle root mismatch for block #{current_block.index}. Expected: {current_block.calculate_merkle_root()}, Found: {current_block.merkle_root}",
                    }
                )

            # Validate diary entries' decryption
            for entry in current_block.diary_entries:
                try:
                    decrypt_data(entry)  # Try to decrypt each diary entry
                except InvalidToken:
                    invalid_blocks.append(
                        {
                            "index": current_block.index,
                            "error": f"Diary entry decryption failed for block #{current_block.index}. Data may have been tampered with.",
                        }
                    )

        # If there are any invalid blocks, print them, otherwise indicate the blockchain is valid
        if invalid_blocks:
            print(
                Fore.RED
                + "The blockchain is invalid. Below are the details of the invalid blocks:"
            )
            for block in invalid_blocks:
                print(f"\nBlock #{block['index']}:")
                print(f"{Fore.YELLOW}Error: {block['error']}")
        else:
            print(Fore.GREEN + "The blockchain is valid and secure.")


# Initialize the blockchain
digital_diary = Blockchain()


def add_new_entry():
    os.system("cls" if os.name == "nt" else "clear")  # Clear the terminal screen
    print(Fore.MAGENTA + Style.BRIGHT + "Add a New Diary Entry\n")
    confirm = input(
        Fore.YELLOW + "Are you sure you want to add a new diary entry? (yes/no): "
    )
    if confirm.lower() == "yes":
        print(
            Fore.WHITE + "Enter your diary entry (type 'done' on a new line to finish):"
        )
        diary_entry_lines = []
        while True:
            line = input(Fore.WHITE + "> ")
            if line.lower() == "done":
                break
            diary_entry_lines.append(line)
        digital_diary.add_entry(diary_entry_lines)  # Pass as a list
        print(Fore.GREEN + "\nYour entry has been added to the blockchain!\n")
    else:
        print(Fore.RED + "\nAction canceled.")
    input(Fore.YELLOW + "\nPress Enter to return to the main menu...")


def view_blockchain():
    os.system("cls" if os.name == "nt" else "clear")  # Clear the terminal screen
    digital_diary.display_blockchain()
    input(Fore.YELLOW + "\nPress Enter to return to the main menu...")


def view_diary_entries():
    os.system("cls" if os.name == "nt" else "clear")  # Clear the terminal screen
    digital_diary.display_diary_entries()
    input(Fore.YELLOW + "\nPress Enter to return to the main menu...")


def main_menu():
    while True:
        os.system("cls" if os.name == "nt" else "clear")  # Clear the terminal screen
        print(Fore.YELLOW + Style.BRIGHT + "=== Blockchain Digital Diary ===")
        print(
            f"{Fore.WHITE}Software Version: {Fore.CYAN}{digital_diary.software_version}"
        )
        print(Fore.WHITE + "1. Add New Diary Entry")
        print(Fore.GREEN + "2. View Blockchain")
        print(Fore.MAGENTA + "3. View Diary Entries Only")
        print(Fore.CYAN + "4. Exit")
        print(Fore.BLUE + "5. Validate Entire Blockchain")

        choice = input(Fore.CYAN + "\nSelect an option (1, 2, 3, 4, or 5): ")

        if choice == "1":
            add_new_entry()
        elif choice == "2":
            view_blockchain()
        elif choice == "3":
            view_diary_entries()
        elif choice == "4":
            confirm_exit = input(
                Fore.YELLOW + "Are you sure you want to exit? (yes/no): "
            )
            if confirm_exit.lower() == "yes":
                print(Fore.RED + "\nExiting the application... Goodbye!")
                break
            else:
                print(Fore.RED + "\nAction canceled.")
                time.sleep(1)
        elif choice == "5":
            digital_diary.validate_entire_blockchain()  # Validate the entire blockchain
            input(Fore.YELLOW + "\nPress Enter to return to the main menu...")
        else:
            print(Fore.RED + "\nInvalid option. Please try again.")
            time.sleep(1)


# Initialize the blockchain securely
if verify_password():
    digital_diary = Blockchain()
    main_menu()
