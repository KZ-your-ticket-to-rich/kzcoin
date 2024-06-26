// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./helpers/MerkleProof.sol";
import "./helpers/SafeTransfer.sol";

contract KzReward is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable
{
    uint96 public constant PERCENTAGE_BASE = 1000;

    address public rewardToken;
    uint96 public conversionRate;
    mapping(uint => bytes32) public merkleRoot;
    mapping(address => mapping(uint => bool)) public claimed; //user > session > status
    mapping(address => bool) public isManager;

    event Claimed(
        address indexed sender,
        uint256 indexed session,
        uint256 amount,
        uint256 actualAmount
    );
    event TakenBack(address token, address receiver, uint256 amount);
    event ManagerUpdated(address manager, bool status);
    event RootProofUpdated(
        uint session,
        bytes32 rootProof,
        bool isRemovePrevious
    );
    event RateUpdated(uint96 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _rewardToken) external initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        rewardToken = _rewardToken;
        isManager[_msgSender()] = true;
        conversionRate = 800; //0.8
    }

    modifier onlyManager() {
        require(isManager[_msgSender()], "ONLY_MANAGER");
        _;
    }

    function deplete(address _token, address _receiver) external {
        takeBack(_token, _receiver, IERC20(_token).balanceOf(address(this)));
    }

    function takeBack(
        address _token,
        address _receiver,
        uint _amount
    ) public onlyOwner {
        SafeTransfer.safeTransfer(_token, _receiver, _amount);
        emit TakenBack(_token, _receiver, _amount);
    }

    function setManager(address _manager, bool _status) external onlyOwner {
        isManager[_manager] = _status;
        emit ManagerUpdated(_manager, _status);
    }

    function setRate(uint96 _rate) external onlyOwner {
        conversionRate = _rate;
        emit RateUpdated(_rate);
    }

    function setRoot(uint _session, bytes32 _merkleRoot) external onlyManager {
        merkleRoot[_session] = _merkleRoot;
        emit RootProofUpdated(_session, _merkleRoot, false);
    }

    function claim(
        uint256 _session,
        uint256 _amount,
        bytes32[] calldata _merkleProof
    ) external nonReentrant {
        address sender = _msgSender();
        _checkAndMark(sender, _session, _amount, _merkleProof);
        uint256 actualAmount = (_amount * conversionRate) / PERCENTAGE_BASE;
        SafeTransfer.safeTransfer(rewardToken, sender, actualAmount);
        emit Claimed(sender, _session, _amount, actualAmount);
    }

    function batchClaim(
        uint256[] calldata _sessions,
        uint256[] calldata _amounts,
        bytes32[][] calldata _merkleProofs
    ) external nonReentrant {
        address sender = _msgSender();
        uint256 len = _sessions.length;
        require(
            len == _amounts.length && len == _merkleProofs.length,
            "INVALID_DATA"
        );
        uint256 totalAmount;
        for (uint256 i; i < len; ) {
            _checkAndMark(sender, _sessions[i], _amounts[i], _merkleProofs[i]);
            totalAmount += _amounts[i];
            emit Claimed(
                sender,
                _sessions[i],
                _amounts[i],
                (_amounts[i] * conversionRate) / PERCENTAGE_BASE
            );
            unchecked {
                ++i;
            }
        }

        uint256 actualAmount = (totalAmount * conversionRate) / PERCENTAGE_BASE;
        SafeTransfer.safeTransfer(rewardToken, sender, actualAmount);
    }

    function _checkAndMark(
        address _sender,
        uint _session,
        uint256 _amount,
        bytes32[] calldata _merkleProof
    ) internal {
        bytes32 node;
        bytes32 root;
        /// @solidity memory-safe-assembly
        assembly {
            let slot := claimed.slot
            mstore(0, _sender)
            mstore(32, slot)
            let outerHash := keccak256(0, 64)
            mstore(0, _session)
            mstore(32, outerHash)
            let hash := keccak256(0, 64)
            let status := sload(hash)
            if gt(status, 0) {
                mstore(0x00, 0x722b0212) //error AlreadyClaimed()
                revert(0x1c, 0x04)
            }
            sstore(hash, 0x1)
        }
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            // Store `sender` at ptr
            mstore(ptr, _sender)
            // Store `_session` at ptr + 32
            mstore(add(ptr, 0x20), _session)
            // Store `_token` at ptr + 64
            mstore(add(ptr, 0x40), _amount)

            // Compute keccak256 hash of the encoded values
            let hash := keccak256(ptr, 0x60) // 0x80 = 128 bytes (4 * 32)

            // Store the hash back in memory
            mstore(ptr, hash)
            // Compute the keccak256 hash of the hash
            node := keccak256(ptr, 0x20) // 0x20 = 32 bytes (size of the hash)
        }
        /// @solidity memory-safe-assembly
        assembly {
            let slot := merkleRoot.slot
            mstore(0, _session)
            mstore(32, slot)
            let hash := keccak256(0, 64)
            root := sload(hash)
        }
        require(MerkleProof.verify(_merkleProof, root, node), "INVALID_PROOF");
    }
}
