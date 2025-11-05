# Loading ATT&CK Knowledge Graph Data

This directory contains scripts and instructions for loading the ATT&CK Knowledge Graph data into various graph databases. The ATT&CK Knowledge Graph is a structured representation of cyber threat intelligence based on the MITRE ATT&CK framework.

1. Download raw data from https://github.com/mitre-attack/attack-stix-data/
2. Use the script `import.sypher` to load data into Neo4j (Adjust the file patth to your setup!)
    ```
    PASSWD="changeme"
    cypher-shell -u neo4j -p $PASSWD -f import.cypher
    ```
