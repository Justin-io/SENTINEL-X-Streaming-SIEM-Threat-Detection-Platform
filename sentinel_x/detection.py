from __future__ import annotations
import uuid
from datetime import datetime,timezone
from pathlib import Path
import yaml
from .schema import NormalizedEvent
from .sigma import adapt_sigma_rule,sigma_matches

class RuleEngine:
    """Evaluates native YAML rules and a documented Sigma syntax subset."""
    def __init__(self,rules_dir:Path):
        self.rules=[]
        for path in sorted(Path(rules_dir).rglob("*.yml")):
            raw=yaml.safe_load(path.read_text(encoding="utf-8"))
            if not raw or raw.get("enabled",True) is False: continue
            if "detection" in raw:
                rule=adapt_sigma_rule(raw); rule["source_file"]=str(path); self.rules.append(rule)
            elif "match" in raw and "id" in raw and "title" in raw:
                raw["source_file"]=str(path); self.rules.append(raw)
            else: raise ValueError(f"Rule file {path} is neither a supported Sigma rule nor SENTINEL-X rule")
    @staticmethod
    def _match(event:NormalizedEvent,rule:dict)->bool:
        data=event.model_dump(mode="python")
        for key,expected in rule.get("match",{}).items():
            actual=data.get(key)
            if isinstance(expected,dict) and "contains" in expected:
                if not actual or expected["contains"].casefold() not in str(actual).casefold(): return False
            elif isinstance(expected,dict) and "in" in expected:
                if actual not in expected["in"]: return False
            elif isinstance(expected,list):
                if actual not in expected: return False
            elif actual!=expected: return False
        return True
    def evaluate(self,event:NormalizedEvent)->list[dict]:
        results=[]; data=event.model_dump(mode="json")
        for rule in self.rules:
            matched=sigma_matches(data,rule["detection"]) if rule.get("sigma") else self._match(event,rule)
            if not matched: continue
            rule_id=str(rule["id"])
            results.append({"alert_id":str(uuid.uuid5(uuid.NAMESPACE_URL,f"{event.event_id}:{rule_id}")),
              "event_id":event.event_id,"rule_id":rule_id,"title":rule["title"],
              "severity":rule["severity"],"technique_ids":rule.get("attack",[]),
              "evidence":{"matcher":"sigma-subset" if rule.get("sigma") else "sentinel-yaml",
                "source_file":rule.get("source_file"),
                "condition":rule.get("detection",{}).get("condition") if rule.get("sigma") else rule.get("match"),
                "matched_criteria":len([k for k in rule.get("detection",{}) if k!="condition"]) if rule.get("sigma") else len(rule.get("match",{})),
                "event_excerpt":data},"created_at":datetime.now(timezone.utc).isoformat()})
        return results
