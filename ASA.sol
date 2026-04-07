// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// --- 1. Mock Verifier (用于模拟真实的 ZK Gas 开销) ---
contract MockGroth16Verifier {
    
    uint256 constant ZK_VERIFY_GAS_COST = 220000;

    function verifyProof(
        uint[2] memory,        // 只保留类型，删掉名字 a
        uint[2][2] memory,     // 只保留类型，删掉名字 b
        uint[2] memory,        // 只保留类型，删掉名字 c
        uint[1] memory         // 只保留类型，删掉名字 input
    ) external view returns (bool) {
        // 模拟昂贵的计算：消耗 Gas 直到达到目标
        uint256 startGas = gasleft();
        while (startGas - gasleft() < ZK_VERIFY_GAS_COST) {
            // 空循环消耗 Gas
        }
        return true;
    }
}

// --- 2. ASA 主合约 ---
contract ASA {
    address public owner;
    uint256 public contingentThreshold;
    MockGroth16Verifier public verifier;
    uint256 public nonce;

    event Executed(string mode, uint256 gasUsed);

    constructor(address _owner, uint256 _threshold) {
        owner = _owner;
        contingentThreshold = _threshold;
        verifier = new MockGroth16Verifier(); // 部署模拟验证器
    }

    // --- 辅助函数：生成需要签名的 Hash ---
    // 在 Remix 中，先调用此函数获取 hash，然后在外面签名
    function getMessageHash(address to, uint256 value, bytes memory data) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), block.chainid, to, value, data, nonce));
    }

    // --- Protocol 1: 小额/低风险交易 ---
    function executeContingent(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 v, bytes32 r, bytes32 s // 拆解签名以便测试
    ) external payable {
        uint256 startGas = gasleft();

        // 1. 策略检查
        require(value <= contingentThreshold, "Over threshold");

        // 2. 验证签名 (ECDSA)
        bytes32 txHash = getMessageHash(to, value, data);
        
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash));
        require(ecrecover(ethSignedHash, v, r, s) == owner, "Invalid signature");

        // 3. 执行
        nonce++;
        (bool success, ) = to.call{value: value}(data);
        require(success, "Execution failed");

        emit Executed("Contingent", startGas - gasleft());
    }

    // --- Protocol 2: 大额/高风险交易 ---
    function executeAuthorized(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 v, bytes32 r, bytes32 s,
        // ZKP 参数 
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c
    ) external payable {
        uint256 startGas = gasleft();

        // 1. 双重验证：先验 ECDSA
        bytes32 txHash = getMessageHash(to, value, data);
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash));
        require(ecrecover(ethSignedHash, v, r, s) == owner, "Invalid signature");

        // 2. 双重验证：再验 ZKP (调用模拟器，消耗真实 Gas)
        uint[1] memory input = [uint256(0)];
        require(verifier.verifyProof(a, b, c, input), "Invalid ZK Proof");

        // 3. 执行
        nonce++;
        (bool success, ) = to.call{value: value}(data);
        require(success, "Execution failed");

        emit Executed("Authorized", startGas - gasleft());
    }
    
    // 充值入口
    receive() external payable {}
}