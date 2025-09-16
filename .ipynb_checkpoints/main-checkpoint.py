
from neo4j import GraphDatabase
import pandas as pd
from typing import Dict, Any, List

# ---------- CONFIG ----------
NEO4J_URI  = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "YourStrongPass123!"

DEFAULTS = {
    "group": "APT29",
    "tech": "Credential Dumping",
    "tactic": "defense-evasion",
    "g1": "APT29",
    "g2": "FIN7",
    "software": "Mimikatz",
    "recent_days": 180,
}

# ---------- UTILS ----------

def df_from_result(result) -> pd.DataFrame:
    rows = [dict(r) for r in result]
    return pd.DataFrame(rows)

class AttackKG:
    def __init__(self, uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def query(self, q: str, **params) -> pd.DataFrame:
        with self.driver.session() as s:
            res = s.run(q, **params)
            return df_from_result(res)

    # ----- Part A -----
    def A1_counts(self):
        q1 = "MATCH (n:Attack) RETURN count(n) AS nodes"
        q2 = "MATCH ()-[r:ATTACK_REL]->() RETURN count(r) AS relationships"
        return self.query(q1), self.query(q2)

    def A2_object_types(self):
        q = """
        MATCH (n:Attack)
        RETURN n.stix_type AS type, count(*) AS n
        ORDER BY n DESC
        """
        return self.query(q)

    def A3_relationship_types(self):
        q = """
        MATCH ()-[r:ATTACK_REL]->()
        RETURN r.rel_type AS rel_type, count(*) AS n
        ORDER BY n DESC
        """
        return self.query(q)

    def A4_tactic_technique_counts(self):
        q = """
        MATCH (tac:Attack {stix_type:'x-mitre-tactic'})<-[:IN_TACTIC]-(tech:Attack {stix_type:'attack-pattern'})
        RETURN tac.shortname AS tactic, count(tech) AS techniques
        ORDER BY techniques DESC
        """
        return self.query(q)

    def A5_active_vs_inactive(self):
        q = """
        MATCH (t:Attack {stix_type:'attack-pattern'})
        RETURN
          sum(CASE WHEN coalesce(t.deprecated,false) OR coalesce(t.revoked,false) THEN 1 ELSE 0 END) AS inactive,
          sum(CASE WHEN NOT coalesce(t.deprecated,false) AND NOT coalesce(t.revoked,false) THEN 1 ELSE 0 END) AS active
        """
        return self.query(q)

    # ----- Part B -----
    def B1_group_techniques(self, group=DEFAULTS["group"]):
        q = """
        WITH toLower($group) AS g
        MATCH (grp:Attack {stix_type:'intrusion-set'})
        WHERE toLower(grp.name) CONTAINS g
        MATCH (grp)-[:ATTACK_REL {rel_type:'uses'}]->(tech:Attack {stix_type:'attack-pattern'})
        OPTIONAL MATCH (tech)-[:IN_TACTIC]->(tac:Attack {stix_type:'x-mitre-tactic'})
        RETURN tac.shortname AS tactic, tech.name AS technique
        ORDER BY tactic, technique
        LIMIT 150
        """
        return self.query(q, group=group)

    def B2_group_software(self, group=DEFAULTS["group"]):
        q = """
        WITH toLower($group) AS g
        MATCH (grp:Attack {stix_type:'intrusion-set'})
        WHERE toLower(grp.name) CONTAINS g
        MATCH (grp)-[:ATTACK_REL {rel_type:'uses'}]->(s:Attack)
        WHERE s.stix_type IN ['tool','malware']
        RETURN s.stix_type AS kind, s.name AS software
        ORDER BY kind, software
        LIMIT 100
        """
        return self.query(q, group=group)

    def B3_group_techniques_via_software(self, group=DEFAULTS["group"]):
        q = """
        WITH toLower($group) AS g
        MATCH (grp:Attack {stix_type:'intrusion-set'})
        WHERE toLower(grp.name) CONTAINS g
        MATCH (grp)-[:ATTACK_REL {rel_type:'uses'}]->(s:Attack)
        WHERE s.stix_type IN ['tool','malware']
        MATCH (s)-[:ATTACK_REL {rel_type:'uses'}]->(tech:Attack {stix_type:'attack-pattern'})
        WITH s, collect(DISTINCT tech.name) AS techniques
        RETURN s.name AS software, techniques
        ORDER BY size(techniques) DESC
        LIMIT 20
        """
        return self.query(q, group=group)

    def B4_technique_users(self, tech=DEFAULTS["tech"]):
        q = """
        WITH toLower($tech) AS t
        MATCH (tech:Attack {stix_type:'attack-pattern'})
        WHERE toLower(tech.name) CONTAINS t
        MATCH (grp:Attack {stix_type:'intrusion-set'})-[:ATTACK_REL {rel_type:'uses'}]->(tech)
        RETURN tech.name AS technique, collect(DISTINCT grp.name) AS groups
        LIMIT 10
        """
        return self.query(q, tech=tech)

    def B5_top_groups_by_techniques(self):
        q = """
        MATCH (g:Attack {stix_type:'intrusion-set'})-[:ATTACK_REL {rel_type:'uses'}]->(t:Attack {stix_type:'attack-pattern'})
        RETURN g.name AS group, count(DISTINCT t) AS techniques
        ORDER BY techniques DESC LIMIT 20
        """
        return self.query(q)

    def B6_shortest_connection_between_groups(self, g1=DEFAULTS["g1"], g2=DEFAULTS["g2"]):
        q = """
        MATCH (a:Attack {stix_type:'intrusion-set'}), (b:Attack {stix_type:'intrusion-set'})
        WHERE toLower(a.name) CONTAINS toLower($g1) AND toLower(b.name) CONTAINS toLower($g2)
        MATCH p = shortestPath((a)-[:ATTACK_REL*..6]-(b))
        RETURN p
        """
        return self.query(q, g1=g1, g2=g2)

    # ----- Part C -----
    def C1_group_mitigations(self, group=DEFAULTS["group"]):
        q = """
        WITH toLower($group) AS g
        MATCH (grp:Attack {stix_type:'intrusion-set'}) WHERE toLower(grp.name) CONTAINS g
        MATCH (grp)-[:ATTACK_REL {rel_type:'uses'}]->(tech:Attack {stix_type:'attack-pattern'})
        MATCH (co:Attack {stix_type:'course-of-action'})<-[:ATTACK_REL {rel_type:'mitigates'}]-(tech)
        RETURN tech.name AS technique, collect(DISTINCT co.name) AS mitigations
        ORDER BY technique LIMIT 50
        """
        return self.query(q, group=group)

    def C2_group_mitigation_gaps(self, group=DEFAULTS["group"]):
        q = """
        WITH toLower($group) AS g
        MATCH (grp:Attack {stix_type:'intrusion-set'}) WHERE toLower(grp.name) CONTAINS g
        MATCH (grp)-[:ATTACK_REL {rel_type:'uses'}]->(tech:Attack {stix_type:'attack-pattern'})
        OPTIONAL MATCH (co:Attack {stix_type:'course-of-action'})<-[:ATTACK_REL {rel_type:'mitigates'}]-(tech)
        WITH tech, count(co) AS c WHERE c = 0
        RETURN tech.name AS unmitigated ORDER BY unmitigated LIMIT 50
        """
        return self.query(q, group=group)

    def C3_detection_coverage_top(self, limit=25):
        q = """
        MATCH (tech:Attack {stix_type:'attack-pattern'})
        OPTIONAL MATCH (dc:Attack {stix_type:'x-mitre-data-component'})-[:ATTACK_REL {rel_type:'detects'}]->(tech)
        RETURN tech.name AS technique, count(dc) AS detectors
        ORDER BY detectors DESC
        LIMIT $limit
        """
        return self.query(q, limit=limit)

    def C4_detections_for_tech(self, tech=DEFAULTS["tech"]):
        q = """
        WITH toLower($tech) AS t
        MATCH (tech:Attack {stix_type:'attack-pattern'}) WHERE toLower(tech.name) CONTAINS t
        OPTIONAL MATCH (dc:Attack {stix_type:'x-mitre-data-component'})-[:ATTACK_REL {rel_type:'detects'}]->(tech)
        OPTIONAL MATCH (ds:Attack {stix_type:'x-mitre-data-source'})-[:ATTACK_REL {rel_type:'detects'}]->(tech)
        RETURN tech.name, collect(DISTINCT dc.name) AS data_components, collect(DISTINCT ds.name) AS data_sources
        """
        return self.query(q, tech=tech)

    # ----- Part D -----
    def D1_tactic_mapping(self, tactic=DEFAULTS["tactic"]):
        q = """
        WITH toLower($tactic) AS tac
        MATCH (t:Attack {stix_type:'x-mitre-tactic'})
        WHERE toLower(t.shortname) = tac OR toLower(t.name) CONTAINS tac
        MATCH (tech:Attack {stix_type:'attack-pattern'})-[:IN_TACTIC]->(t)
        RETURN t.shortname AS tactic, collect(tech.name)[0..25] AS sample_techniques, count(tech) AS total
        """
        return self.query(q, tactic=tactic)

    def D2_subtechniques(self):
        q = """
        MATCH (sub:Attack {stix_type:'attack-pattern'})-[:ATTACK_REL {rel_type:'subtechnique-of'}]->(parent:Attack {stix_type:'attack-pattern'})
        RETURN parent.name AS technique, collect(sub.name) AS subtechniques
        ORDER BY size(subtechniques) DESC
        LIMIT 20
        """
        return self.query(q)

    def D3_techniques_by_platform(self):
        q = """
        UNWIND ['windows','linux','macos','azure','aws','gcp','saas','office 365','network'] AS platform
        MATCH (tech:Attack {stix_type:'attack-pattern'})
        WHERE platform IN [p IN coalesce(tech.platforms,[]) | toLower(p)]
        RETURN platform, count(tech) AS technique_count
        ORDER BY technique_count DESC
        """
        return self.query(q)

    def D4_domain_breakdown(self):
        q = """
        UNWIND ['enterprise-attack','mobile-attack','ics-attack'] AS dom
        MATCH (n:Attack)
        WHERE dom IN [d IN coalesce(n.domains,[]) | toLower(d)]
        RETURN dom AS domain, count(n) AS nodes
        ORDER BY nodes DESC
        """
        return self.query(q)

    def D5_recently_modified(self, recent_days=DEFAULTS["recent_days"]):
        q = """
        MATCH (t:Attack {stix_type:'attack-pattern'})
        WHERE t.modified >= datetime() - duration({days:$days})
        RETURN t.name AS technique, t.modified
        ORDER BY t.modified DESC
        LIMIT 25
        """
        return self.query(q, days=recent_days)

    # ----- Part E -----
    def E3_software_pivot(self, software=DEFAULTS["software"]):
        q = """
        WITH toLower($software) AS q
        MATCH (s:Attack) WHERE s.stix_type IN ['tool','malware'] AND toLower(s.name) CONTAINS q
        OPTIONAL MATCH (g:Attack {stix_type:'intrusion-set'})-[:ATTACK_REL {rel_type:'uses'}]->(s)
        OPTIONAL MATCH (s)-[:ATTACK_REL {rel_type:'uses'}]->(tech:Attack {stix_type:'attack-pattern'})
        RETURN s.name AS software, collect(DISTINCT g.name) AS groups, collect(DISTINCT tech.name)[0..25] AS techniques
        """
        return self.query(q, software=software)


def _print_section(title: str, df: pd.DataFrame):
    print(f"\\n=== {title} ===")
    if df is None:
        print("(no results)")
        return
    if df.empty:
        print("(empty)")
    else:
        # limit very wide cells for terminal readability
        with pd.option_context("display.max_colwidth", 80, "display.width", 140):
            print(df.to_string(index=False))

def demo():
    atk = AttackKG()
    try:
        # Part A
        nodes_df, rels_df = atk.A1_counts()
        _print_section("A1 counts — nodes", nodes_df)
        _print_section("A1 counts — relationships", rels_df)

        _print_section("A2 object types", atk.A2_object_types())
        _print_section("A3 relationship types", atk.A3_relationship_types())
        _print_section("A4 tactic -> technique counts", atk.A4_tactic_technique_counts())
        _print_section("A5 techniques active vs inactive", atk.A5_active_vs_inactive())

        # Part B
        _print_section("B1 techniques used by group", atk.B1_group_techniques(DEFAULTS["group"]))
        _print_section("B2 software used by group", atk.B2_group_software(DEFAULTS["group"]))
        _print_section("B3 techniques via software", atk.B3_group_techniques_via_software(DEFAULTS["group"]))
        _print_section("B4 groups that use a technique", atk.B4_technique_users(DEFAULTS["tech"]))
        _print_section("B5 top groups by techniques", atk.B5_top_groups_by_techniques())
        _print_section("B6 shortest connection between groups", atk.B6_shortest_connection_between_groups(DEFAULTS["g1"], DEFAULTS["g2"]))

        # Part C
        _print_section("C1 mitigations for group's techniques", atk.C1_group_mitigations(DEFAULTS["group"]))
        _print_section("C2 mitigation gaps", atk.C2_group_mitigation_gaps(DEFAULTS["group"]))
        _print_section("C3 detection coverage (top techniques)", atk.C3_detection_coverage_top(25))
        _print_section("C4 data components/sources for technique", atk.C4_detections_for_tech(DEFAULTS["tech"]))

        # Part D
        _print_section("D1 tactic mapping", atk.D1_tactic_mapping(DEFAULTS["tactic"]))
        _print_section("D2 parent -> subtechniques", atk.D2_subtechniques())
        _print_section("D3 techniques by platform", atk.D3_techniques_by_platform())
        _print_section("D4 domain breakdown", atk.D4_domain_breakdown())
        _print_section("D5 recently modified techniques", atk.D5_recently_modified(DEFAULTS["recent_days"]))

        # Part E
        _print_section("E3 software pivot", atk.E3_software_pivot(DEFAULTS["software"]))

    finally:
        atk.close()

if __name__ == "__main__":
    demo()