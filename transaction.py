import json
from web3 import Web3, HTTPProvider
from solcx import compile_files, set_solc_version

class Transactor:
    def __init__(self):
        # truffle development blockchain address
        self.blockchain_address = 'http://127.0.0.1:9545'
        # Client instance to interact with the blockchain
        self.web3 = Web3(HTTPProvider(self.blockchain_address))
        # web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        print(self.web3.isConnected())

        self.pkey = "d584bf8171cc6e7e635b82c14861b0f7e9c6a0b4ba05669839d74952d6b21ec2"

        # Set the default account (so we don't need to set the "from" for every transaction call)
        self.acct = self.web3.eth.account.from_key(self.pkey)
        self.web3.eth.default_account = self.acct.address

        print(self.acct.address)

        # exit()

        # Deployed contract address (see `migrate` command output: `contract address`)
        self.deployed_contract_address = '0x0E94765C2A64958F0F04a172c1F320E7bbF4d736'

        set_solc_version("v0.5.16")
        compiled_sol = compile_files(["./contracts/metacoin-box/contracts/Storage.sol"])
        contract_id, contract_interface = compiled_sol.popitem()
        bytecode = contract_interface['bin']
        abi = contract_interface['abi']

        # Fetch deployed contract reference
        self.contract = self.web3.eth.contract(address=self.deployed_contract_address, abi=abi)

    def getTest(self, index):
        message = self.contract.functions.testGet(index).call()
        print(message)

    def getEntitySignPubKey(self, entityName: bytes):
        # str.encode('Alice')
        message = self.contract.functions.getEntitySignPubKey(entityName).call()
        print(message)

    def getCertNum(self, entityName_uri: bytes):
        message = self.contract.functions.getCertNum(entityName_uri).call()
        print(message)

    def getCert(self, entityName_uri: bytes, index):
        # str.encode('Alice')
        message = self.contract.functions.getCert(entityName_uri, index).call()
        print(message)

    def newEntity(self, entityName: bytes, signPubKey: bytes, attestPubKey: bytes):
        # str.encode('Alice')
        # str.encode('1111111111111111111222222')
        tx_hash = self.contract.functions.newEntity(entityName, signPubKey, attestPubKey).transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        print(tx_receipt)

    def uploadCert(self, entityName_uri: bytes, cert: bytes):
        tx_hash = self.contract.functions.newEntity(entityName_uri, cert).transact()
        tx_receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
        print(tx_receipt)