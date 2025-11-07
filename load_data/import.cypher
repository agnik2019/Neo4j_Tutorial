CREATE CONSTRAINT attack_id IF NOT EXISTS
FOR (n:Attack) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT attack_rel_id IF NOT EXISTS
FOR ()-[r:ATTACK_REL]-() REQUIRE r.id IS UNIQUE;

CREATE INDEX attack_name IF NOT EXISTS FOR (n:Attack) ON (n.name);

CALL apoc.periodic.iterate(
  "
  UNWIND ['file:///enterprise-attack/enterprise-attack.json', 'file:///mobile-attack/mobile-attack.json', 'file:///ics-attack/ics-attack.json'] AS f
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
  {batchSize:1000}
);

CALL apoc.periodic.iterate(
  "
  UNWIND ['file:///enterprise-attack/enterprise-attack.json', 'file:///mobile-attack/mobile-attack.json', 'file:///ics-attack/ics-attack.json'] AS f
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
  {batchSize:1000}
);

MATCH (tech:Attack {stix_type:'attack-pattern'})
UNWIND coalesce(tech.kc_phases, []) AS phase
MATCH (tac:Attack {stix_type:'x-mitre-tactic'})
WHERE toLower(tac.shortname) = toLower(phase)
MERGE (tech)-[:IN_TACTIC]->(tac);

MATCH (n:Attack) RETURN count(n) AS nodes;
MATCH ()-[r:ATTACK_REL]->() RETURN count(r) AS relationships;
MATCH (:Attack {stix_type:'attack-pattern'})-[:IN_TACTIC]->(:Attack {stix_type:'x-mitre-tactic'})
RETURN count(*) AS technique_tactic_links;