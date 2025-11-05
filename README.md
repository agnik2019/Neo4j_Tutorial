## **What is the ATT&CK Knowledge Graph?**

The MITRE ATT&CK Knowledge Graph (AttackKG) represents the Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) framework as a connected graph.

In plain terms, it turns MITRE ATT&CK's structured cybersecurity data into nodes (entities) and relationships (edges) that can be explored and analyzed using Neo4j.

## **Structure of the Graph:** Each ATT&CK concept becomes a **node** in the graph with a type and properties. Each logical link (like _uses_, _mitigates_, or _in_tactic_) becomes a **relationship** between two nodes

| **ATT&CK Concept** | **STIX Type (stix_type)** | **Example Node Label** | **Typical Property Fields** |
| --- | --- | --- | --- |
| Intrusion Set (Group) | intrusion-set | :Attack | name, description, aliases |
| --- | --- | --- | --- |
| Technique | attack-pattern | :Attack | name, external_id, x_mitre_platforms |
| --- | --- | --- | --- |
| Sub-Technique | also attack-pattern (with dot IDs) | :Attack | name, external_id |
| --- | --- | --- | --- |
| Software (Tool or Malware) | tool, malware | :Attack | name, stix_type, description |
| --- | --- | --- | --- |
| Tactic | x-mitre-tactic | :Attack | name, x_mitre_shortname |
| --- | --- | --- | --- |
| Mitigation | course-of-action | :Attack | name, description |
| --- | --- | --- | --- |

**Some Key Relationship Types :**

| **Relationship** | **Meaning** | **Example** |
| --- | --- | --- |
| uses | A group or software uses a technique or another software | APT28 → uses → Credential Dumping |
| --- | --- | --- |
| mitigates | A mitigation prevents or reduces a technique | MFA → mitigates → Credential Dumping |
| --- | --- | --- |
| subtechnique-of | A sub-technique belongs to a parent technique | PowerShell (T1059.001) → subtechnique-of → Command Execution (T1059) |
| --- | --- | --- |

# 🧠 MITRE ATT&CK STIX → Neo4j Import Script

This guide provides a Cypher script to import MITRE ATT&CK data (Enterprise, Mobile, and ICS STIX bundles) into a Neo4j database.  
It loads the STIX objects as nodes and relationships, applies constraints for consistency, and builds helper links to make common queries easier and faster.

---

## ⚙️ Prerequisites

- **Neo4j 5.x+**
- **APOC plugin** enabled
- MITRE ATT&CK STIX bundles located in the Neo4j import directory:
  - `enterprise-attack.json`
  - `mobile-attack.json`
  - `ics-attack.json`

---
Dataset: https://attack.mitre.org/, https://github.com/mitre-attack/attack-stix-data 

## 0️⃣ Define STIX Bundle Locations

Point to the three ATT&CK STIX bundles that reside in the Neo4j `import` folder.

```cypher
:param files => [
  "file:///enterprise-attack/enterprise-attack.json",
  "file:///mobile-attack/mobile-attack.json",
  "file:///ics-attack/ics-attack.json"
];
```

```cypher
// ----------------------------------------------------------------------------
// 1) Constraints (idempotent)
// ----------------------------------------------------------------------------
CREATE CONSTRAINT attack_id IF NOT EXISTS
FOR (n:Attack) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT attack_rel_id IF NOT EXISTS
FOR ()-[r:ATTACK_REL]-() REQUIRE r.id IS UNIQUE;

// (Optional but handy for name lookups)
CREATE INDEX attack_name IF NOT EXISTS FOR (n:Attack) ON (n.name);

// ----------------------------------------------------------------------------
// 2) Load ALL non-relationship STIX objects as :Attack nodes
//    (techniques, sub-techniques, tactics, tools, malware, groups, mitigations, etc.)
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "
  UNWIND $files AS f
  CALL apoc.load.json(f) YIELD value
  UNWIND value.objects AS obj
  WITH obj
  WHERE obj.type <> 'relationship'
  RETURN obj
  ",
  "
  MERGE (a:Attack {id: obj.id})
  SET a.stix_type  = obj.type,
      a.name       = coalesce(obj.name, obj.x_mitre_shortname),
      a.description= obj.description,
      a.created    = CASE WHEN obj.created  IS NOT NULL THEN datetime(obj.created)  END,
      a.modified   = CASE WHEN obj.modified IS NOT NULL THEN datetime(obj.modified) END,
      a.revoked    = coalesce(obj.revoked, false),
      a.deprecated = coalesce(obj.x_mitre_deprecated, false),
      a.platforms  = coalesce(obj.x_mitre_platforms, []),
      a.domains    = coalesce(obj.x_mitre_domains, []),
      a.kc_phases  = [p IN coalesce(obj.kill_chain_phases, []) | p.phase_name],
      a.shortname  = obj.x_mitre_shortname
  ",
  {params:{files:$files}, batchSize:1000, parallel:true}
);

// ----------------------------------------------------------------------------
// 3) Load STIX relationship objects as :ATTACK_REL edges
//    Keeps the STIX relationship_type in r.rel_type (uses, mitigates, detects, subtechnique-of, ...)
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "
  UNWIND $files AS f
  CALL apoc.load.json(f) YIELD value
  UNWIND value.objects AS obj
  WITH obj
  WHERE obj.type = 'relationship'
  RETURN obj
  ",
  "
  MATCH (s:Attack {id: obj.source_ref})
  MATCH (t:Attack {id: obj.target_ref})
  MERGE (s)-[r:ATTACK_REL {id: obj.id}]->(t)
    SET r.rel_type    = obj.relationship_type,
        r.description = obj.description
  ",
  {params:{files:$files}, batchSize:1000, parallel:true}
);

// ----------------------------------------------------------------------------
// 4) Helper edges: Technique -> Tactic membership via kill_chain_phases
//    (makes tactic queries easy/fast)
// ----------------------------------------------------------------------------
MATCH (tech:Attack {stix_type:'attack-pattern'})
UNWIND coalesce(tech.kc_phases, []) AS phase
MATCH (tac:Attack {stix_type:'x-mitre-tactic'})
WHERE toLower(tac.shortname) = toLower(phase)
MERGE (tech)-[:IN_TACTIC]->(tac);

// ----------------------------------------------------------------------------
// 5) Quick sanity checks
// ----------------------------------------------------------------------------
MATCH (n:Attack) RETURN count(n) AS nodes;
MATCH ()-[r:ATTACK_REL]->() RETURN count(r) AS relationships;
MATCH (:Attack {stix_type:'attack-pattern'})-[:IN_TACTIC]->(:Attack {stix_type:'x-mitre-tactic'})
RETURN count(*) AS technique_tactic_links;
```

# MITRE ATT&CK Neo4j Import Script

## 1️⃣ Create Constraints and Indexes (Idempotent)

Ensure unique IDs for nodes and relationships and create indexes for faster lookups.

```cypher
CREATE CONSTRAINT attack_id IF NOT EXISTS
FOR (n:Attack) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT attack_rel_id IF NOT EXISTS
FOR ()-[r:ATTACK_REL]-() REQUIRE r.id IS UNIQUE;

-- Optional but useful for lookup by name
CREATE INDEX attack_name IF NOT EXISTS FOR (n:Attack) ON (n.name);
```

## **Level 1 - Easy (Query Warm-ups)**

### **1) List all labels and their counts (top 10)**

MATCH (n)

UNWIND labels(n) AS label

RETURN label, count(\*) AS count

ORDER BY count DESC

LIMIT 10;

### **2) List all relationship types and their counts (top 10)**

MATCH ()-\[r\]->()

RETURN type(r) AS type, count(r) AS count

ORDER BY count DESC

LIMIT 10;

### **3) STIX-type buckets under :Attack**

MATCH (a:Attack)

RETURN a.stix_type AS stix_type, count(a) AS count

ORDER BY count DESC;

### **4) Show 10 sample :Attack nodes**

MATCH (a:Attack)

RETURN a.name AS name, a.stix_type AS stix_type, a.id AS id

LIMIT 10;

### **5) 20 technique names alphabetically**

MATCH (t:Attack {stix_type: 'attack-pattern'})

RETURN t.name AS technique

ORDER BY technique

LIMIT 20;

### **6) 20 intrusion-set (group) names alphabetically**

MATCH (g:Attack {stix_type: 'intrusion-set'})

RETURN g.name AS group

ORDER BY group

LIMIT 20;

### **7) 20 software names (tool/malware)**

MATCH (s:Attack)

WHERE s.stix_type IN \['tool','malware'\]

RETURN s.name AS software, s.stix_type AS kind

ORDER BY software

LIMIT 20;

### **8) All ATT&CK tactics (x-mitre-tactic) shortnames**

MATCH (t:Attack {stix_type: 'x-mitre-tactic'})

RETURN DISTINCT t.name AS tactic, t.x_mitre_shortname AS shortname

ORDER BY shortname;

### **9) 20 mitigation names**

MATCH (m:Attack {stix_type: 'course-of-action'})

RETURN m.name AS mitigation

ORDER BY mitigation

LIMIT 20;

### **10) Key ATT&CK links present (by ATTACK_REL.rel_type)**

MATCH ()-\[r:ATTACK_REL\]->()

RETURN r.rel_type AS relationship_type, count(r) AS count

ORDER BY count DESC

LIMIT 10;

## **Level 2 - Multistep (Analytics & Joins)**

### **1) Software overlap for a technique term (e.g., "malicious file")**

WITH toLower('malicious file') AS term

MATCH (t:Attack {stix_type:'attack-pattern'})

WHERE toLower(t.name) CONTAINS term

MATCH (g:Attack {stix_type:'intrusion-set'})-\[:ATTACK_REL {rel_type:'uses'}\]->(t)

MATCH (g)-\[:ATTACK_REL {rel_type:'uses'}\]->(s:Attack)

WHERE s.stix_type IN \['tool','malware'\]

RETURN s.name AS software, s.stix_type AS kind,

count(DISTINCT g) AS group_count,

collect(DISTINCT g.name)\[0..5\] AS sample_groups

ORDER BY group_count DESC, software;

### **2) Top-3 techniques for a group by software implementations + mitigations (e.g., "APT28")**

WITH 'APT28' AS groupName

MATCH (g:Attack {stix_type:'intrusion-set', name:groupName})-\[:ATTACK_REL {rel_type:'uses'}\]->(s:Attack)

WHERE s.stix_type IN \['tool','malware'\]

MATCH (s)-\[:ATTACK_REL {rel_type:'uses'}\]->(tech:Attack {stix_type:'attack-pattern'})

OPTIONAL MATCH (m:Attack {stix_type:'course-of-action'})-\[:ATTACK_REL {rel_type:'mitigates'}\]->(tech)

RETURN tech.name AS technique,

count(DISTINCT s) AS software_count,

collect(DISTINCT m.name)\[0..5\] AS mitigations

ORDER BY software_count DESC, technique

LIMIT 3;

**3) Most-used sub-techniques under the "execution" tactic and who uses them**

// Level 2 - Q3: Most-used sub-techniques under the "execution" tactic and who uses them

MATCH (ta:Attack {stix_type:'x-mitre-tactic'})

WHERE toLower(ta.name) = 'execution' // match the Execution tactic safely

MATCH (sub:Attack {stix_type:'attack-pattern'})-\[:IN_TACTIC\]->(ta)

WHERE EXISTS {

(sub)-\[:ATTACK_REL {rel_type:'subtechnique-of'}\]->(:Attack {stix_type:'attack-pattern'})

} // keep only sub-techniques via explicit relation

MATCH (g:Attack {stix_type:'intrusion-set'})-\[:ATTACK_REL {rel_type:'uses'}\]->(sub)

RETURN sub.name AS sub_technique,

count(DISTINCT g) AS group_count,

collect(DISTINCT g.name)\[0..5\] AS top_groups

ORDER BY group_count DESC, sub_technique

LIMIT 10;

### **4) Shared tactics between two software families (e.g., "rar" and "PsExec")**

:param s1 => 'rar';

:param s2 => 'psexec';

:param k => 8;

// Q4 - Shared tactics between two software families (CONTAINS match, schema-safe)

WITH toLower(\$s1) AS a, toLower(\$s2) AS b

// match all software whose names contain the terms (tool|malware)

MATCH (s1:Attack)

WHERE s1.stix_type IN \['tool','malware'\] AND toLower(s1.name) CONTAINS a

WITH a, b, collect(DISTINCT s1) AS s1s

MATCH (s2:Attack)

WHERE s2.stix_type IN \['tool','malware'\] AND toLower(s2.name) CONTAINS b

WITH s1s, collect(DISTINCT s2) AS s2s

// expand pairs; go software -> techniques -> tactic (same tactic node)

UNWIND s1s AS s1

UNWIND s2s AS s2

MATCH (s1)-\[:ATTACK_REL {rel_type:'uses'}\]->(t1:Attack {stix_type:'attack-pattern'})

MATCH (s2)-\[:ATTACK_REL {rel_type:'uses'}\]->(t2:Attack {stix_type:'attack-pattern'})

MATCH (t1)-\[:IN_TACTIC\]->(ta:Attack {stix_type:'x-mitre-tactic'})

MATCH (t2)-\[:IN_TACTIC\]->(ta)

// show shared tactic and example techniques from each software

RETURN s1.name AS s1_name,

s2.name AS s2_name,

coalesce(ta.shortname, ta.name) AS shared_tactic,

collect(DISTINCT t1.name)\[0..\$k\] AS s1_tech_examples,

collect(DISTINCT t2.name)\[0..\$k\] AS s2_tech_examples

ORDER BY s1_name, s2_name, shared_tactic;

### **5) Unmitigated software risks**

MATCH (s:Attack)

WHERE s.stix_type IN \['tool','malware'\]

MATCH (s)-\[:ATTACK_REL {rel_type:'uses'}\]->(tech:Attack {stix_type:'attack-pattern'})

MATCH (g:Attack {stix_type:'intrusion-set'})-\[:ATTACK_REL {rel_type:'uses'}\]->(tech)

WHERE NOT ( (:Attack {stix_type:'course-of-action'})-\[:ATTACK_REL {rel_type:'mitigates'}\]->(tech) )

RETURN DISTINCT s.name AS software, tech.name AS technique, g.name AS example_group

ORDER BY software, technique

LIMIT 20;

### **6) Technique → Tactic coverage for a given group (e.g., APT29)**

// Q6 - technique → tactic coverage for a given group

WITH 'APT29' AS group_name, 5 AS examples_per_tactic

WITH toLower(group_name) AS gname, toInteger(examples_per_tactic) AS K

MATCH (g:Attack {stix_type:'intrusion-set'})

WHERE toLower(g.name) CONTAINS gname

// group -> techniques

MATCH (g)-\[:ATTACK_REL {rel_type:'uses'}\]->(t:Attack {stix_type:'attack-pattern'})

// technique -> tactic

MATCH (t)-\[:IN_TACTIC\]->(ta:Attack {stix_type:'x-mitre-tactic'})

WITH ta.shortname AS tactic, collect(DISTINCT t.name) AS techs, K

RETURN tactic,

size(techs) AS techniques_count,

techs\[0..K\] AS example_techniques

ORDER BY techniques_count DESC, tactic;

## **Level 3 - Graph-Algorithm Flavored**

## **1) Centrality of techniques**

/\* Rank techniques by distinct neighbors: (# groups using it) + (# software using it) \*/

MATCH (tech:Attack {stix_type:'attack-pattern'})

OPTIONAL MATCH (tech)<-\[:ATTACK_REL {rel_type:'uses'}\]-(g:Attack {stix_type:'intrusion-set'})

WITH tech, collect(DISTINCT g.name) AS groups

OPTIONAL MATCH (tech)<-\[:ATTACK_REL {rel_type:'uses'}\]-(s:Attack)

WHERE s.stix_type IN \['tool','malware'\]

WITH tech, groups, collect(DISTINCT s.name) AS software

WITH tech, size(groups) + size(software) AS degree

RETURN tech.name AS technique, degree

ORDER BY degree DESC, technique

LIMIT 20;

### **2) Community-like "attack kits" via 2-hop uses ego-components**

// Level 3 - Q2: Community-like "attack kits" via 'uses' only (4 hops), APOC-free, fixed limits

MATCH (seed:Attack {stix_type:'intrusion-set'})

WITH seed

ORDER BY seed.name

LIMIT 120

CALL {

WITH seed

MATCH p = (seed)-\[:ATTACK_REL\*1..4\]-(m:Attack)

WHERE m.stix_type IN \['intrusion-set','tool','malware','attack-pattern'\]

AND ALL(r IN relationships(p) WHERE r.rel_type = 'uses')

WITH seed, collect(DISTINCT m) AS ms // keep seed in scope for the next line

RETURN ms + \[seed\] AS nodes // return only 'nodes'

}

UNWIND nodes AS n

WITH nodes, min(elementId(n)) AS component_key

UNWIND nodes AS n

WITH component_key, collect(DISTINCT n) AS comp_nodes

WITH component_key,

\[x IN comp_nodes WHERE x.stix_type = 'intrusion-set' | x.name\] AS groups,

\[x IN comp_nodes WHERE x.stix_type IN \['tool','malware'\] | x.name\] AS software,

\[x IN comp_nodes WHERE x.stix_type = 'attack-pattern' | x.name\] AS techniques

WITH component_key, groups, software, techniques,

size(groups) AS n_groups,

size(software) AS n_software,

size(techniques) AS n_techniques

RETURN component_key,

n_groups,

n_software,

n_techniques,

(n_groups + n_software + n_techniques) AS size_total,

groups\[0..10\] AS example_groups,

software\[0..10\] AS example_software,

techniques\[0..10\] AS example_techniques

ORDER BY size_total DESC, n_groups DESC, n_software DESC, n_techniques DESC

LIMIT 25;

### **3) Link prediction (techniques a group might adopt next) - software-backed**

WITH 'APT1' AS groupName

/\* Known software for the group \*/

MATCH (g:Attack {stix_type:'intrusion-set', name:groupName})-\[:ATTACK_REL {rel_type:'uses'}\]->(s:Attack)

WHERE s.stix_type IN \['tool','malware'\]

/\* Known techniques for the group \*/

OPTIONAL MATCH (g)-\[:ATTACK_REL {rel_type:'uses'}\]->(known:Attack {stix_type:'attack-pattern'})

WITH g, collect(DISTINCT known) AS knownTechs, collect(DISTINCT s) AS sw

/\* Candidate techniques used by that software but not already known to the group \*/

UNWIND sw AS s1

MATCH (s1)-\[:ATTACK_REL {rel_type:'uses'}\]->(cand:Attack {stix_type:'attack-pattern'})

WHERE NOT cand IN knownTechs

WITH cand, count(DISTINCT s1) AS supporting_software

ORDER BY supporting_software DESC, cand.name

RETURN cand.name AS predicted_technique, supporting_software AS score

LIMIT 15;
