contract_orders = [i for i in range(1, 51)]

bug_types = [
    {
        "tool": "Oyente",
        "bugs": [
            "Re-entrancy",
            "Timestamp-Dependency",
            "Unhandled-Exceptions",
            "TOD",
            "Overflow-Underflow",
        ],
    },
    {
        "tool": "Securify",
        "bugs": ["Re-entrancy", "Unchecked-Send", "Unhandled-Exceptions", "TOD"],
    },
    {
        "tool": "Mythril",
        "bugs": [
            "Re-entrancy",
            "Timestamp-Dependency",
            "Unchecked-Send",
            "Unhandled-Exceptions",
            "Overflow-Underflow",
            "tx.origin",
        ],
    },
    {
        "tool": "Smartcheck",
        # Contracts
        "bugs": [
            "Re-entrancy",
            "Timestamp-Dependency",
            "Unhandled-Exceptions",
            "Overflow-Underflow",
            "tx.origin",
        ],
    },
    {"tool": "Manticore", "bugs": ["Re-entrancy", "Overflow-Underflow"]},
    {
        "tool": "Slither",
        "bugs": [
            "Re-entrancy",
            "Timestamp-Dependency",
            "Unhandled-Exceptions",
            "tx.origin",
        ],
    },
    {
        "tool": "CrossFuzz",
        "bugs": [
            # Valid
            # "Overflow-Underflow",
            "Re-entrancy",
            # "TOD",
            # "Unhandled-Exceptions",
            # Invalid
            # "Timestamp-Dependency",
            # "Unchecked-Send",
            # "tx-origin",
        ],
    },
]

contract_names_per_file = [
    {"file": "buggy_1.sol", "names": ["EIP20Interface", "HotDollarsToken"]},
    {"file": "buggy_2.sol", "names": ["CareerOnToken"]},
    {"file": "buggy_3.sol", "names": ["CareerOnToken"]},
    {"file": "buggy_4.sol", "names": ["PHO"]},
    {"file": "buggy_5.sol", "names": ["Ownable", "TokenERC20", "TTC"]},
    {"file": "buggy_6.sol", "names": ["Ownable", "ChannelWallet"]},
    {"file": "buggy_7.sol", "names": ["Ownable", "AccountWallet"]},
    {"file": "buggy_8.sol", "names": ["Ownable", "TokenERC20", "YFT"]},
    {"file": "buggy_9.sol", "names": ["Ownable", "XLToken"]},
    {"file": "buggy_10.sol", "names": ["DocumentSigner"]},
    {
        "file": "buggy_11.sol",
        "names": [
            "ERC20Interface",
            "ApproveAndCallFallBack",
            "Owned",
            "ForTheBlockchain",
        ],
    },
    {
        "file": "buggy_12.sol",
        "names": [
            "ERC20",
            "ERC223ReceivingContract",
            "ERC223",
            "ERC223Token",
            "Owned",
            "Grand",
        ],
    },
    {"file": "buggy_13.sol", "names": ["BitCash"]},
    {"file": "buggy_14.sol", "names": ["ERC20", "ERC20Detailed", "SaveWon"]},
    {"file": "buggy_15.sol", "names": ["MD"]},
    {"file": "buggy_16.sol", "names": ["ERC20Interface", "Owned", "ExclusivePlatform"]},
    {"file": "buggy_17.sol", "names": ["owned", "TokenERC20", "AZT"]},
    {
        "file": "buggy_18.sol",
        "names": ["ERC20Interface", "ApproveAndCallFallBack", "Owned", "_Yesbuzz"],
    },
    {"file": "buggy_19.sol", "names": ["owned", "ethBank"]},
    {
        "file": "buggy_20.sol",
        "names": [
            "Ownable",
            "Stoppable",
            "RampInstantPoolInterface",
            "RampInstantEscrowsPoolInterface",
            "RampInstantPool",
            "RampInstantEthPool",
        ],
    },
    {"file": "buggy_21.sol", "names": ["Token", "StableDEX"]},
    {
        "file": "buggy_22.sol",
        "names": ["owned", "tokenRecipient", "Token", "MindsyncPlatform"],
    },
    {
        "file": "buggy_23.sol",
        "names": ["Proxy", "UpgradeabilityProxy", "AdminUpgradeabilityProxy"],
    },
    {"file": "buggy_24.sol", "names": ["FomoFeast"]},
    {"file": "buggy_25.sol", "names": ["WhiteBetting"]},
    {"file": "buggy_26.sol", "names": ["UBBCToken"]},
    {"file": "buggy_27.sol", "names": ["Ownable", "ERC20Detailed", "DanPanCoin"]},
    {"file": "buggy_28.sol", "names": ["ERC20Detailed", "HYDROGEN"]},
    {
        "file": "buggy_29.sol",
        "names": [
            "ERC20Interface",
            "IERC20Interface",
            "RaffleToken",
            "RaffleTokenExchange",
        ],
    },
    {
        "file": "buggy_30.sol",
        "names": ["ERC777", "MinterRole", "PauserRole", "Pausable", "SKYBITToken"],
    },
    {
        "file": "buggy_31.sol",
        "names": ["Ownable", "ReentrancyGuard", "FeeTransactionManager"],
    },
    {
        "file": "buggy_32.sol",
        "names": ["ERC20TokenInterface", "ERC20Token", "AsseteGram"],
    },
    {"file": "buggy_33.sol", "names": ["Owned", "Token", "Staking"]},
    {"file": "buggy_34.sol", "names": ["Ownable", "LollypopToken"]},
    {"file": "buggy_35.sol", "names": ["owned", "BitpayerDEX"]},
    {
        "file": "buggy_36.sol",
        "names": ["owned", "tokenRecipient", "Token", "MindsyncPlatform"],
    },
    {
        "file": "buggy_37.sol",
        "names": [
            "SafeMath",
            "ERC20Interface",
            "ApproveAndCallFallBack",
            "Owned",
            "AugustCoin",
        ],
    },
    {"file": "buggy_38.sol", "names": ["ERC20Detailed", "BIGBOMBv2"]},
    {"file": "buggy_39.sol", "names": ["TAMCContract"]},
    {"file": "buggy_40.sol", "names": ["ERC20", "ERC20Detailed", "SimpleSwapCoin"]},
    {"file": "buggy_41.sol", "names": ["AO"]},
    {"file": "buggy_42.sol", "names": ["Owned", "Token", "Staking"]},
    {
        "file": "buggy_43.sol",
        "names": [
            "EventMetadata",
            "Operated",
            "MultiHashWrapper",
            "ProofHash",
            "Template",
            "Post",
        ],
    },
    {
        "file": "buggy_44.sol",
        "names": [
            "EventMetadata",
            "Operated",
            "ProofHashes",
            "MultiHashWrapper",
            "Template",
            "Feed",
        ],
    },
    {"file": "buggy_45.sol", "names": ["StockBet"]},
    {"file": "buggy_46.sol", "names": ["ProofOfExistence"]},
    {"file": "buggy_47.sol", "names": ["ERC20Interface", "AcunarToken", "AcunarIEO"]},
    {
        "file": "buggy_48.sol",
        "names": ["ERC20Interface", "ApproveAndCallFallBack", "Owned", "QurasToken"],
    },
    {"file": "buggy_49.sol", "names": ["TAMC"]},
    {"file": "buggy_50.sol", "names": ["digitalNotary"]},
]
