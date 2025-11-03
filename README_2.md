# Neo4j Hands-on Guide

## 1) From Tables to Graphs: Fundamental Concepts

### Relational (tabular)
- **Data units:** tables → rows → columns  
- **Identity & joins:** PK/FK; join paths are fixed at design time  
- **Query style:** `SELECT` with `JOIN`s (must name the join path)  
- **Strengths:** well-structured facts, transactions/ledgers, reports, set math  

### Graph (Labeled Property Graph, LPG)
- **Data units:** nodes (with labels), relationships (with types & direction), both have properties  
- **Identity & links:** first-class edges connect records directly; multi-hop queries are natural  
- **Query style:** pattern matching with variable-length paths  
- **Strengths:** highly connected data, exploratory questions, unknown/variable joins, path analytics  

**Edges as first-class citizens**
- Relationships can carry properties (`{since, confidence, weight}`), time, provenance, etc.  
- Easy to model many-to-many and multi-hop structures without join tables.  

**When to use which**
- Relational: stable, highly structured OLTP (orders, inventory, accounting).  
- Graph: when relationships dominate (identity resolution, knowledge bases, fraud, recommendations).  

---

## 2) Schema & Ontology: Designing the Structure

### Relational recap
- ER diagrams, normalization (1NF/2NF/3NF), strong typing, PK/FK constraints.  

### LPG schema elements
- **Labels:** `(:Technique)`, `(:Group)`, `(:Tool)`  
- **Relationship types:** `[:USES]`, `[:MITIGATES]`, `[:IN_TACTIC]`  
- **Properties:** strings, numbers, booleans, arrays  
- **Constraints & indexes:**  
  ```cypher
  CREATE CONSTRAINT attack_id IF NOT EXISTS
  FOR (n:Attack) REQUIRE n.id IS UNIQUE;
  ```

### RDF/OWL (ontology) at a glance
- Triples: subject–predicate–object IRIs, classes & properties  
- Ontologies standardize vocabulary  
- Mapping to LPG: classes → labels, properties → rel types, triples → edges  

### Parallels (RDB → Graph)
- Tables with PK → node labels with a unique key  
- Join tables → relationships (with props)  
- Foreign keys → relationship endpoints  

### Design patterns
- Star, snowflake/galaxy, tree, path  
- Multi-label nodes: e.g., `(:Software:AssetComponent)`  
- Bridge entity for hyperedges: e.g., `(:Transaction)`  

---

## 3) Data Normalization & Modeling Principles
- RDB normalization: reduce redundancy, ensure integrity.  
- Graphs: identity = node, connection = edge.  
- Selective denormalization for faster traversals.  
- Use reification for property-rich relationships.  
- Supernodes okay if intentional (e.g., `(:Country)`).  
- Duplicate values if needed for frequent queries (with refresh job).  

---

## 4) Ingesting Data & Transactions

### Neo4j ingestion patterns
- **Idempotent writes:** use `MERGE` with `ON CREATE/ON MATCH`  
- **Batching:** use `apoc.periodic.iterate`  
- **Schema evolution:** `IF NOT EXISTS` constraints  

**Examples:**

```cypher
// Load nodes
LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
MERGE (n:Entity {id: row.id})
SET n += apoc.map.clean(row, ['id'], []);

// Load relationships
LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
MATCH (s:Entity {id: row.src}), (t:Entity {id: row.dst})
MERGE (s)-[r:REL {id: row.edge_id}]->(t)
SET r.type = row.type, r.weight = toFloat(row.weight);
```

**Batch import:**
```cypher
CALL apoc.periodic.iterate(
  'LOAD CSV WITH HEADERS FROM "file:///edges.csv" AS row RETURN row',
  'MATCH (s:Entity {id: row.src}),(t:Entity {id: row.dst})
   MERGE (s)-[:REL {id: row.edge_id}]->(t)',
  {batchSize: 5000, parallel: false}
);
```

---

## 5) Query Languages: OpenCypher (LPG) vs SPARQL (RDF)

### SPARQL (RDF)
```sparql
SELECT ?tech WHERE {
  ?tech a attack:Technique ;
        attack:inTactic attack:DefenseEvasion .
}
```

### OpenCypher (LPG)
```cypher
MATCH (tech:Attack {stix_type:'attack-pattern'})-[:IN_TACTIC]->(tac:Attack {stix_type:'x-mitre-tactic'})
WHERE toLower(tac.shortname) = 'defense-evasion'
RETURN tech.name;
```

**Thinking shift:**  
- SQL joins → explicit graph patterns  
- Variable-length traversals → `[:KNOWS*1..2]`

---

## 6) Advanced Analysis

Examples:
```cypher
// Count techniques per group
MATCH (g:Attack {stix_type:'intrusion-set'})-[:ATTACK_REL {rel_type:'uses'}]->(t:Attack {stix_type:'attack-pattern'})
RETURN g.name, count(DISTINCT t) AS techniques
ORDER BY techniques DESC LIMIT 20;
```

Graph algorithms with GDS:
```cypher
CALL gds.graph.project('attackUses','Attack',{ATTACK_REL:{type:'ATTACK_REL'}});
CALL gds.pageRank.stream('attackUses')
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name AS node, score
ORDER BY score DESC LIMIT 20;
```

---

## 7) Use Case Deep Dives

- **7a) Attack Surface Modeling**: MITRE ATT&CK dataset (STIX 2.1)  
- **7b) Customer 360 Views**: (Customer)-[:PLACED]->(Order)-[:CONTAINS]->(Product)  
- **7c) Fraud Detection**: Transaction graphs with (Account)-[:TX]->(Account)  

All include **warm-up queries, pivots, coverage gaps, shortest paths**.

---

## Setup Instructions

1. **Create project folders**
   ```bash
   mkdir -p ~/neo4j-project/{import,plugins}
   cd neo4j-project
   mv ~/Downloads/triples.csv ./import/
   ```

2. **Docker compose file**
   ```yaml
   version: "3.9"
   services:
     neo4j:
       image: neo4j:5.22.0
       container_name: neo4j-container
       ports:
         - "7474:7474"
         - "7687:7687"
       environment:
         NEO4J_AUTH: neo4j/YourStrongPass123!
         NEO4J_PLUGINS: '["apoc"]'
         NEO4J_apoc_import_file_enabled: "true"
         NEO4J_server_directories_import: "/import"
       volumes:
         - neo4j_data:/data
         - ./import:/import
         - ./plugins:/plugins
   volumes:
     neo4j_data:
   ```

3. **Start Neo4j**
   ```bash
   docker compose up -d
   docker ps --filter name=neo4j-container
   ```

4. **Access UI**
   - Browser: http://localhost:7474  
   - User: `neo4j`  
   - Pass: `YourStrongPass123!`

5. **Create uniqueness constraint**
   ```cypher
   CREATE CONSTRAINT entity_name_unique IF NOT EXISTS
   FOR (e:Entity) REQUIRE e.name IS UNIQUE;
   ```

6. **Load triples**
   ```cypher
   LOAD CSV WITH HEADERS FROM 'file:///triples.csv' AS row
   WITH trim(row.head) AS h, trim(row.relation) AS r, trim(row.tail) AS t
   WHERE h <> '' AND r <> '' AND t <> ''
   MERGE (h:Entity {name: h})
   MERGE (t:Entity {name: t})
   WITH h, t, toUpper(replace(r,' ','_')) AS rtype
   CALL apoc.create.relationship(h, rtype, {}, t) YIELD rel
   RETURN count(rel) AS created;
   ```

---

## Dataset: MITRE ATT&CK
- **Domains:** Enterprise, Mobile, ICS  
- **Objects:** techniques, tactics, groups, malware, tools, mitigations, data components  
- **Edges:** uses, mitigates, detects, subtechnique-of, in_tactic  

---

## Exercises

### Part A — Warm-up
- Count nodes, relationships, object types  
- Which tactics have most techniques?  
- Active vs deprecated  

### Part B — Threat-Intel Pivots
- Techniques used by group  
- Software a group uses  
- Which groups use a technique  

### Part C — Defense Coverage
- Mitigations for techniques  
- Coverage gaps (no mitigations)  
- Detection coverage  

### Part D — Structure & Taxonomy
- Tactic ↔ techniques mapping  
- Subtechniques hierarchy  
- Platform/domain breakdown  
- Recently modified techniques  

### Part E — Scenarios
- Build mitigation backlog  
- Choose detections for tactic  
- Pivot via software  

---
