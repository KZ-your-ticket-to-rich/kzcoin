// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC20Capped } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract KzToken is Ownable, ERC20Capped {
    using SafeMath for uint256;
    uint256 public constant TOKEN_CAPPED = 21_000 * (10 ** 9) * (10 ** 18);
    uint256 public maxHoldingAmount;
    uint256 public minHoldingAmount;
    uint256 public maxTxAmount;
    address admin;
    bool public limited;
    bool public started;
    mapping(address => bool) public swapPairs;

    // Anti-bot and anti-whale mappings and variables
    mapping(address => bool) public blacklists;

    // Some dapps need to be allowed to transfer large amounts of tokens
    mapping(address => bool) public allowedDapps;

    event ConfigUpdated(
        bool started,
        bool limited,
        uint256 maxHoldingAmount,
        uint256 minHoldingAmount,
        uint256 maxTxAmount
    );
    event BlacklistUpdated(address, bool);
    event SwapPairUpdated(address, bool);
    event DappUpdated(address, bool);
    event AdminUpdated(address);

    constructor() ERC20Capped(TOKEN_CAPPED) ERC20("KZ", "KZ") {
        admin = msg.sender;
        _mint(msg.sender, TOKEN_CAPPED);
    }

    function config(
        bool _started,
        bool _limited,
        uint256 _maxHoldingAmount,
        uint256 _minHoldingAmount,
        uint256 _maxTxAmount
    ) external onlyOwner {
        started = _started;
        limited = _limited;
        maxHoldingAmount = _maxHoldingAmount;
        minHoldingAmount = _minHoldingAmount;
        maxTxAmount = _maxTxAmount;
        emit ConfigUpdated(_started, _limited, _maxHoldingAmount, _minHoldingAmount, _maxTxAmount);
    }

    function setSwapPair(address _pair, bool _status) external onlyOwner {
        swapPairs[_pair] = _status;
        emit SwapPairUpdated(_pair, _status);
    }

    function setWhitelistDapp(address _dapp, bool _status) external onlyOwner {
        allowedDapps[_dapp] = _status;
        emit DappUpdated(_dapp, _status);
    }

    function setBlacklist(address _addr, bool _isBlacklisting) public onlyOwner {
        blacklists[_addr] = _isBlacklisting;
        emit BlacklistUpdated(_addr, _isBlacklisting);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
        require(!blacklists[to] && !blacklists[from], "BLACKLISTED");

        if (!started) {
            require(from == owner() || to == owner(), "TRADING_IS_NOT_START");
            return;
        }
        if (allowedDapps[msg.sender]) {
            return;
        }
        if (maxTxAmount > 0) {
            require(amount <= maxTxAmount, "TX_LIMIT_EXCEEDED");
        }
        if (limited && swapPairs[from]) {
            require(
                super.balanceOf(to) + amount <= maxHoldingAmount && super.balanceOf(to) + amount >= minHoldingAmount,
                "FORBIDDEN"
            );
        }
    }

    function burn(uint256 value) external {
        _burn(msg.sender, value);
    }

    function transferAdmin(address _newAdmin) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        admin = _newAdmin;
        emit AdminUpdated(_newAdmin);
    }

    function claimStuckTokens(address _token) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        IERC20(_token).transfer(msg.sender, IERC20(_token).balanceOf(address(this)));
    }
}
