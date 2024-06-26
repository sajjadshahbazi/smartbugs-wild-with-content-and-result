# smartbugs wild with content and result

```
def read_text_file(file_path, name):
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        words = runTasks(smartContractContent)
        # Example: Accessing word embeddings
        print(words)
        model = Word2Vec([words], vector_size=100, window=5, min_count=1, sg=0)
        print(model.wv.vectors)

        print(name)
        # print(smartContractContent)
        isVulnarable = gerResultVulnarable(name)
        print(isVulnarable)
        print("======================================================================================")
        return isVulnarable
```

        
After inspecting all 35 analysis tools presented in Table 1, we found 9 tools that meet the inclusion criteria outlined. Table 2 presents the excluded and included tools, and for the excluded ones, it also shows which criteria they did not meet.
- HoneyBadger is developed by a group of researchers at the University of Luxembourg and is an Oyente-based (see below) tool that employs symbolic execution and a set of heuristics to pinpoint honeypots in smart contracts. Honeypots are smart contracts that appear to have an obvious flaw in their design, which allows an arbitrary user to drain Ether2 from the contract, given that the user transfers a priori a certain amount of Ether to the contract. When HoneyBadger detects that a contract appears to be vulnerable, it means that the developer of the contract wanted to make the contract look vulnerable, but is not vulnerable.
- Maian, developed jointly by researchers from the National University of Singapore and University College London, is also based on the Oyente tool. Maian looks for contracts that can be self destructed or drained of Ether from arbitrary addresses, or that accept Ether but do not have a payout functionality. A dynamic analysis in a private blockchain is then used to reduce the number of false positives.
- Manticore, developed by TrailOfBits, also uses symbolic execution to find execution paths in EVM bytecode that lead to reentrancy vulnerabilities and reachable self-destruct operations.
- Mythril, developed by ConsenSys, relies on concolic analysis, taint analysis and control flow checking of the EVM bytecode to prune the search space and to look for values that allow exploiting vulnerabilities in the smart contract.
- Osiris, developed by a group of researchers at the University of Luxembourg, extends Oyente to detect integer bugs in smart contracts.
- Oyente, developed by Melonport AG, is one of the first smart contract analysis tools. It is also used as a basis for several other approaches like Maian and Osiris. Oyente uses symbolic execution on EVM bytecode to identify vulnerabilities.
- Securify, developed by ICE Center at ETH Zurich, statically analyzes EVM bytecode to infer relevant and precise semantic information about the contract using the Souffle Datalog solver. It then checks compliance and violation patterns that capture sufficient conditions for proving if a property holds or not.
- Slither, developed by TrailOfBits, is a static analysis framework that converts Solidity smart contracts into an intermediate representation called SlithIR and applies known program analysis techniques such as dataflow and taint tracking to extract and refine information. 
Smartcheck [39], developed by SmartDec, is a static analysis tool that looks for vulnerability patterns and bad coding practices. It runs lexical and syntactical analysis on Solidity source code.


What is the accuracy of current analysis tools in detecting vulnerabilities on Solidity smart contracts? By combining the 9 tools together, they are only able to detect 42% of all the vulnerabilities. This shows that there is still room to improve the accuracy of the current approaches to detect vulnerabilities in smart contracts. We observe that the tools underperform to detect vulnerabilities in the following three categories: Access Control, Denial of service, and Front running. They are unable to detect by design vulnerabilities from Bad Randomness and Short Addresses categories. We also observe that Mythril outperforms the other tools by the number of detected vulnerabilities (31/115, 27%) and by the number of vulnerability categories that it targets (5/9 categories). The combination of Mythril and Slither allows detecting a total of 42/115 (37%) vulnerabilities, which is the best trade-off between accuracy and execution costs.


To answer the second research question, we analyzed the ability of the 9 selected tools to detect vulnerabilities in the contracts from the dataset sbwild (described in Section 2.3.2). We followed the same methodology as in the previous research question, however, for sbwild, we do not have an oracle to identify the vulnerabilities. Table 7 presents the results of executing the 9 tools on the 47,518 contracts. It shows that the 9 tools are able to detect eight different categories of vulnerabilities. Note that the vulnerabilities detected by HoneyBadger are contracts that look vulnerable but are not. They are designed to look vulnerable in order to steal Ether from people that tries to exploit the vulnerability. In total, 44,589 contracts (93%) have at least one vulnerability detected by one of the 9 tools. Such a high number of vulnerable contracts suggests the presence of a considerable number of false positives. Oyente is the approach that identifies the highest number of contracts as vulnerable (73%), mostly due to vulnerabilities in the Arithmetic category. This observation is coherent with the observation of Parizi et al. [34 ], since they determine that Oyente has the highest number of false positives when compared to Mythril, Securify, and Smartcheck. Since we observed a potentially large number of false positives, we analyzed to what extent the tools agree in vulnerabilities they flag. The hypothesis is that if a vulnerability is identified exclusively by a single tool, the probability of it being a false positive increases. Figure 1 presents the results of this analysis. This figure shows the proportion of detected vulnerabilities that have been identified exclusively by one tool alone, two tools, three tools, and finally by four or more tools. HoneyBadger has a peculiar, but useful role: if HoneyBadger detects a vulnerability, it actually means that the vulnerability does not exist. So, consensus with HoneyBadger suggests the presence of false positives.
