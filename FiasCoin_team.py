import hashlib as hasher
import datetime as date
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import json
from flask import Flask
from flask import request

SALT = "445a75d93716bda03075072cf101dd2e6205dc21759cea8d8a0c7eae5e270a83"

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        sha = hasher.sha256()
        sha.update(str(self.index) +
                   str(self.timestamp) +
                   str(self.data) +
                   str(self.previous_hash))
        return sha.hexdigest()


def create_genesis_block():
    # Manually construct a block with
    # index zero and arbitrary previous hash
    return Block(0, date.datetime.now(), {"proof-of-work": 1, "transactions": []}, "0")


blockchain = [create_genesis_block()]
previous_block = blockchain[0]

node = Flask(__name__)

def get_for_field_in_blockchain(search_field, search_value, get_field):
    for block in blockchain:
        for transaction in block.data['transactions']:
            if search_field in transaction.keys():
                if transaction[search_field] == search_value:
                    if get_field in transaction.keys():
                        return transaction[get_field]
                    else:
                        print "\n" + "No such field: " + getfield
    return False


# Store the transactions that
# this node has in a list
this_nodes_transactions = []
file_id = 0

print file_id


@node.route('/txion', methods=['POST'])
def transaction():
    if request.method == 'POST':
        # On each new POST request,
        # we extract the transaction data
        new_txion = request.get_json()
        # Then we add the transaction to our list

        # Because the transaction was successfully
        # submitted, we log it to our console
        if "file" in new_txion.keys():
            condition = new_txion["condition"]
            sha = hasher.sha256()
            sha.update(str(condition))
            key = sha.hexdigest()
            obj = AES.new(key[:32], AES.MODE_CBC, 'This is an IV456')
            message = new_txion["file"] + SALT
            message = message + str("0" * (32 - len(message) % 32))
            ciphertext = b64encode(obj.encrypt(message))
            global file_id
            print "New transaction"
            print "FROM: {}".format(new_txion["from"])
            print "FILE: {}\n".format(ciphertext)
            print "FILE_ID: {}\n".format(file_id)
            # Then we let the client know it worked out
            new_txion["file"] = ciphertext
            new_txion[unicode("file_id")] = unicode(file_id)
            file_id += 1
            new_txion.pop('condition', None)
            this_nodes_transactions.append(new_txion)
            return "\n" + "File added successfully, file_id = {}\n".format(file_id - 1)

        if "get" in new_txion.keys():
            search_field = new_txion['get'].split()[0]
            search_value = new_txion['get'].split()[1]
            get_value = new_txion['get'].split()[2]
            print "Wanna get: ", search_field, search_value, get_value
            if get_for_field_in_blockchain(search_field, search_value, get_value):
                cyphertext = b64decode(get_for_field_in_blockchain(search_field, search_value, get_value))
            else:
                return "\n" + "No such file."

            for field in new_txion.keys():
                nominate_key = str(field) + ':' + str(new_txion[field])
                print "Nominate_key:", nominate_key
                print "Cyphertext:", cyphertext
                sha = hasher.sha256()
                sha.update(str(nominate_key))
                key = sha.hexdigest()
                obj = AES.new(key[:32], AES.MODE_CBC, 'This is an IV456')
                text = obj.decrypt(cyphertext)
                pos = text.find(SALT)
                if pos != -1:
                    return "\n" + text[:pos]

            return "\n" + "Permission denied."

        this_nodes_transactions.append(new_txion)

        print "New transaction"
        print "FROM: {}".format(new_txion['from'])
        print "TO: {}".format(new_txion['to'])
        print "AMOUNT: {}\n".format(new_txion['amount'])
        # Then we let the client know it worked out
        return "\n" + "Transaction submission successful\n"


miner_address = "q3nf394hjg-random-miner-address-34nf3i4nflkn3oi"


def proof_of_work(last_proof):
    # Create a variable that we will use to find
    # our next proof of work
    incrementor = last_proof + 1
    # Keep incrementing the incrementor until
    # it's equal to a number divisible by 9
    # and the proof of work of the previous
    # block in the chain
    while not (incrementor % 9 == 0 and incrementor % last_proof == 0):
        incrementor += 1
    # Once that number is found,
    # we can return it as a proof
    # of our work
    return incrementor


@node.route('/mine', methods=['GET'])
def mine():
    # Get the last proof of work
    last_block = blockchain[-1]
    last_proof = last_block.data['proof-of-work']
    # Find the proof of work for
    # the current block being mined
    # Note: The program will hang here until a new
    #       proof of work is found
    proof = proof_of_work(last_proof)
    # Once we find a valid proof of work,
    # we know we can mine a block so
    # we reward the miner by adding a transaction
    this_nodes_transactions.append(
        {"from": "network", "to": miner_address, "amount": 1}
    )
    # Now we can gather the data needed
    # to create the new block
    new_block_data = {
        "proof-of-work": proof,
        "transactions": list(this_nodes_transactions)
    }
    new_block_index = last_block.index + 1
    new_block_timestamp = this_timestamp = date.datetime.now()
    last_block_hash = last_block.hash
    # Empty transaction list
    this_nodes_transactions[:] = []
    # Now create the
    # new block!
    mined_block = Block(
        new_block_index,
        new_block_timestamp,
        new_block_data,
        last_block_hash
    )
    blockchain.append(mined_block)
    # Let the client know we mined a block
    return json.dumps({
        "index": new_block_index,
        "timestamp": str(new_block_timestamp),
        "data": new_block_data,
        "hash": last_block_hash
    }) + "\n"


@node.route('/blocks', methods=['GET'])
def get_blocks():
    chain_to_send = []
    # Convert our blocks into dictionaries
    # so we can send them as json objects later
    for block in blockchain:
        block_index = str(block.index)
        block_timestamp = str(block.timestamp)
        block_data = str(block.data)
        block_hash = block.hash
        block = {
            "index": block_index,
            "timestamp": block_timestamp,
            "data": block_data,
            "hash": block_hash
        }
        chain_to_send.append(block)
        # Send our chain to whomever requested it
    chain_to_send = json.dumps(chain_to_send)
    return chain_to_send


def find_new_chains():
    # Get the blockchains of every
    # other node
    other_chains = []
    for node_url in peer_nodes:
        # Get their chains using a GET request
        block = requests.get(node_url + "/blocks").content
        # Convert the JSON object to a Python dictionary
        block = json.loads(block)
        # Add it to our list
        other_chains.append(block)
    return other_chains


def consensus():
    # Get the blocks from other nodes
    other_chains = find_new_chains()
    # If our chain isn't longest,
    # then we store the longest chain
    longest_chain = blockchain
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    # If the longest chain wasn't ours,
    # then we set our chain to the longest
    blockchain = longest_chain


node.run()