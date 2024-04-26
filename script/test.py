from solcx import compile_source

# تعریف یک قرارداد هوشمند Solidity
contract_source = """
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint storedData;

    function set(uint x) public {
        storedData = x;
    }

    function get() public view returns (uint) {
        return storedData;
    }
}
"""

# کامپایل کردن قرارداد هوشمند
compiled_contract = compile_source(contract_source)

# نمایش نتیجه کامپایل
print(compiled_contract)
