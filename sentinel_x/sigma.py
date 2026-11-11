"""Explicit Sigma subset evaluator. Unsupported modifiers/conditions fail closed."""
from __future__ import annotations
import fnmatch
import ipaddress
import re
from typing import Any

FIELD_MAP = {"Image":"process_name","ParentImage":"process_parent_name","CommandLine":"process_command_line",
 "ParentCommandLine":"process_parent_command_line","ProcessId":"process_pid","ParentProcessId":"process_parent_pid",
 "Computer":"host_name","Hostname":"host_name","User":"user_name","TargetFilename":"file_path",
 "DestinationIp":"destination_ip","DestinationPort":"destination_port","SourceIp":"source_ip",
 "SourcePort":"source_port","Protocol":"network_protocol","EventID":"event_id_code","EventType":"event_action"}

def _field(event: dict[str, Any], name: str):
    mapped=FIELD_MAP.get(name,name)
    if mapped in event: return event[mapped]
    raw=event.get("raw_event") or {}
    return raw.get(name,raw.get(mapped))

def _one_value(actual, expected, modifiers):
    if "exists" in modifiers: return (actual is not None) is bool(expected)
    if actual is None: return False
    values=expected if isinstance(expected,list) else [expected]
    def compare(wanted):
        left,right=actual,wanted
        for modifier in modifiers:
            if modifier=="all": continue
            if modifier=="contains": return str(right).casefold() in str(left).casefold()
            if modifier=="startswith": return str(left).casefold().startswith(str(right).casefold())
            if modifier=="endswith": return str(left).casefold().endswith(str(right).casefold())
            if modifier=="re": return re.search(str(right),str(left),re.I) is not None
            if modifier=="cidr":
                try: return ipaddress.ip_address(str(left)) in ipaddress.ip_network(str(right),strict=False)
                except ValueError: return False
            if modifier in {"gt","gte","lt","lte"}:
                try: a,b=float(left),float(right)
                except (ValueError,TypeError): return False
                return {"gt":a>b,"gte":a>=b,"lt":a<b,"lte":a<=b}[modifier]
            if modifier=="windash":
                left=str(left).replace("–","-").replace("—","-").replace("−","-")
                right=str(right).replace("–","-").replace("—","-").replace("−","-")
                continue
            raise ValueError(f"Unsupported Sigma modifier: {modifier}")
        if isinstance(left,str) and isinstance(right,str):
            if "*" in right or "?" in right: return fnmatch.fnmatchcase(left.casefold(),right.casefold())
            return left.casefold()==right.casefold()
        return left==right
    matches=[compare(v) for v in values]
    return all(matches) if "all" in modifiers else any(matches)

def _selector_matches(event, selector):
    for expr,expected in selector.items():
        parts=expr.split("|")
        if not _one_value(_field(event,parts[0]),expected,parts[1:]): return False
    return True

_TOKEN=re.compile(r"\s*(\(|\)|\bAND\b|\bOR\b|\bNOT\b|\bALL\b|\bOF\b|\d+|[A-Za-z_][\w.*?-]*)\s*",re.I)

class _ConditionParser:
    def __init__(self,condition,selections,event):
        self.tokens=[]; pos=0
        while pos<len(condition):
            m=_TOKEN.match(condition,pos)
            if not m: raise ValueError(f"Unsupported Sigma condition near: {condition[pos:pos+24]!r}")
            self.tokens.append(m.group(1)); pos=m.end()
        self.index=0; self.selections=selections; self.event=event
    def peek(self): return self.tokens[self.index] if self.index<len(self.tokens) else None
    def take(self):
        value=self.peek()
        if value is not None: self.index+=1
        return value
    def parse(self):
        value=self.parse_or()
        if self.peek() is not None: raise ValueError(f"Unexpected Sigma condition token: {self.peek()}")
        return value
    def parse_or(self):
        value=self.parse_and()
        while (self.peek() or "").casefold()=="or":
            self.take(); right=self.parse_and(); value=value or right
        return value
    def parse_and(self):
        value=self.parse_unary()
        while (self.peek() or "").casefold()=="and":
            self.take(); right=self.parse_unary(); value=value and right
        return value
    def parse_unary(self):
        token=self.peek()
        if token is None: raise ValueError("Unexpected end of Sigma condition")
        if token.casefold()=="not":
            self.take(); return not self.parse_unary()
        if token=="(":
            self.take(); value=self.parse_or()
            if self.take()!=")": raise ValueError("Unclosed parenthesis in Sigma condition")
            return value
        if token.isdigit() or token.casefold()=="all":
            quantifier=self.take().casefold()
            if (self.take() or "").casefold()!="of": raise ValueError("Expected 'of' after Sigma quantifier")
            pattern=self.take()
            if pattern is None: raise ValueError("Missing Sigma selection pattern")
            names=[n for n in self.selections if not n.startswith("_") and (pattern.casefold()=="them" or fnmatch.fnmatchcase(n,pattern))]
            if not names: return False
            count=sum(_selector_matches(self.event,self.selections[n]) for n in names)
            return count >= (len(names) if quantifier=="all" else int(quantifier))
        name=self.take()
        if name.casefold()=="them":
            names=[n for n in self.selections if not n.startswith("_")]
            return bool(names) and all(_selector_matches(self.event,self.selections[n]) for n in names)
        if name not in self.selections: raise ValueError(f"Unknown Sigma selection: {name}")
        return _selector_matches(self.event,self.selections[name])

def sigma_matches(event: dict[str,Any],detection:dict[str,Any])->bool:
    selections={k:v for k,v in detection.items() if k!="condition" and isinstance(v,dict)}
    condition=detection.get("condition")
    if not isinstance(condition,str) or not condition.strip(): raise ValueError("Sigma detection.condition must be a non-empty string")
    return _ConditionParser(condition,selections,event).parse()

def adapt_sigma_rule(rule:dict[str,Any])->dict[str,Any]:
    if not isinstance(rule.get("detection"),dict): raise ValueError("Sigma rule must include a detection mapping")
    if not rule.get("title"): raise ValueError("Sigma rule must include a title")
    level=str(rule.get("level","medium")).lower()
    severity={"informational":"info","low":"low","medium":"medium","high":"high","critical":"critical"}.get(level)
    if severity is None: raise ValueError(f"Unsupported Sigma level: {level}")
    tags=rule.get("tags") or []
    attack=sorted({tag.split(".",1)[1].upper() for tag in tags if tag.lower().startswith("attack.") and re.fullmatch(r"t[0-9]{4}(?:\.[0-9]{3})?",tag.split(".",1)[1],re.I)})
    return {"id":str(rule.get("id") or rule["title"]),"title":rule["title"],
      "description":rule.get("description",""),"severity":severity,"attack":attack,
      "sigma":True,"detection":rule["detection"],"logsource":rule.get("logsource",{})}
