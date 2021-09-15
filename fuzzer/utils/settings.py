#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

# Ethereum VM ('homestead', 'byzantium' or 'petersburg')
EVM_VERSION = "petersburg"
# Size of population
POPULATION_SIZE = None
# Number of generations
GENERATIONS = 10
# Global timeout in seconds
GLOBAL_TIMEOUT = None
# Probability of crossover
PROBABILITY_CROSSOVER = 0.9
# Probability of mutation
PROBABILITY_MUTATION = 0.1
# Maximum number of symbolic execution calls before restting population
MAX_SYMBOLIC_EXECUTION = 10
# Solver timeout in milliseconds
SOLVER_TIMEOUT = 100
# List of attacker accounts
ATTACKER_ACCOUNTS = ["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
# Default gas limit for sending transactions
GAS_LIMIT = 4500000
# Default gas price for sending transactions
GAS_PRICE = 10
# Default account balance
ACCOUNT_BALANCE = 100000000*(10**18)
# Maximum length of individuals
MAX_INDIVIDUAL_LENGTH = 5
# Logging level
LOGGING_LEVEL = logging.INFO
# Block height
BLOCK_HEIGHT = 'latest'
# RPC Host
RPC_HOST = 'localhost'
# RPC Port
RPC_PORT = 8545
# True = Remote fuzzing, False = Local fuzzing
REMOTE_FUZZING = False
# True = Environmental instrumentation enabled, False = Environmental instrumentation disabled
ENVIRONMENTAL_INSTRUMENTATION = True
# run until first bug is detected
RUN_UNTIL_FIRST_BUG = False

DETECT_ARBITRARY_MEM = True
DETECT_ASSERTION_FAIL = True
DETECT_INTEGER_OVERFLOW = True
DETECT_REENTRANCY = True
DETECT_TRANSACTION_ORDER_DEPENDENCY = True
DETECT_BLOCK_DEPENDENCY = True
DETECT_UNHANDLED_EXCEPTION = True
DETECT_UNSAFE_DELEGATECALL = True
DETECT_LEAKING_ETHER = True
DETECT_LOCKING_ETHER = True
DETECT_SELFDESTRUCT = True
