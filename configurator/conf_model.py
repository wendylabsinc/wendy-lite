"""Configurator model: attributes, relations, dependency graph and solver.

The master configuration (configurator/master_conf.yaml) has two lists:

attributes
    Each item maps a name to a type ("string" or "size") and an optional
    enum of allowed values. A size is an integer number of bytes; the YAML
    can write it with a KiB, MiB or GiB unit. An attribute can be undefined.

relations
    Each item has an optional "if" condition, a "then" list of attribute
    values and/or a "sdkconfig" text block. When the condition is true, the
    relation sets the attributes and appends the lines to the intrinsic
    "sdkconfig" attribute.

An attribute depends on each attribute in the condition of a relation that
sets it. The solver evaluates the relations in the order of this graph.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import graphlib
import operator
import re
from typing import Any, Iterator, Union

import yaml

SDKCONFIG = "sdkconfig"
TYPES = ("string", "size")
FORMAT_VERSIONS = ("1.0",)  # format_version values that this code reads
VALUES_FILE = "values file"
COMMAND_LINE = "command line"

_SIZE_UNITS = {"KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}
_SIZE_RE = re.compile(r"^\s*(\d+)\s*(KiB|MiB|GiB)?\s*$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ConfError(Exception):
    """The master configuration or the values file is not valid."""


@contextmanager
def _where(location: str) -> Iterator[None]:
    """Add a location prefix to a ConfError raised in the block."""
    try:
        yield
    except ConfError as e:
        raise ConfError(f"{location}: {e}") from None


# --- Values and attributes -------------------------------------------------


def parse_size(raw: Any) -> int:
    """Return a size in bytes. Accept an int or a text such as "8MiB"."""
    if isinstance(raw, int) and not isinstance(raw, bool):
        if raw >= 0:
            return raw
    elif isinstance(raw, str):
        m = _SIZE_RE.match(raw)
        if m:
            return int(m.group(1)) * _SIZE_UNITS.get(m.group(2), 1)
    raise ConfError(f"{raw!r} is not a size (use a number with an optional KiB, MiB or GiB unit)")


def format_size(n: int) -> str:
    for unit in ("GiB", "MiB", "KiB"):
        mult = _SIZE_UNITS[unit]
        if n and n % mult == 0:
            return f"{n} ({n // mult} {unit})"
    return str(n)


@dataclass
class Attribute:
    name: str
    type: str
    enum: list[Any] | None = None

    def convert(self, raw: Any) -> Any:
        """Convert a YAML value to the attribute type. No enum check."""
        if self.type == "size":
            return parse_size(raw)
        if isinstance(raw, str):
            return raw
        raise ConfError(f"{raw!r} is not a string (put quotes around it)")

    def normalize(self, raw: Any) -> Any:
        """Convert a YAML value to the attribute type and check the enum."""
        with _where(self.name):
            value = self.convert(raw)
            if self.enum is not None and value not in self.enum:
                allowed = ", ".join(self.format(v) for v in self.enum)
                raise ConfError(f"{self.format(value)} is not one of: {allowed}")
        return value

    def format(self, value: Any) -> str:
        if value is None:
            return "<undefined>"
        if self.type == "size":
            return format_size(value)
        return str(value)


# --- Conditions ------------------------------------------------------------

_COMPARE = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}
_ORDERING = {"<", "<=", ">", ">="}


@dataclass
class Compare:
    attr: Attribute
    op: str
    value: Any

    def attrs(self) -> set[str]:
        return {self.attr.name}

    def eval(self, values: dict[str, Any]) -> bool:
        actual = values.get(self.attr.name)
        if actual is None:
            # An undefined attribute is equal to no value.
            return self.op == "!="
        return _COMPARE[self.op](actual, self.value)

    def __str__(self) -> str:
        literal = f'"{self.value}"' if self.attr.type == "string" else str(self.value)
        return f"{self.attr.name} {self.op} {literal}"


@dataclass
class Not:
    operand: Node

    def attrs(self) -> set[str]:
        return self.operand.attrs()

    def eval(self, values: dict[str, Any]) -> bool:
        return not self.operand.eval(values)

    def __str__(self) -> str:
        if isinstance(self.operand, Not):
            return f"!{self.operand}"
        return f"!({self.operand})"


@dataclass
class BoolOp:
    op: str  # "&&" or "||"
    operands: list[Node]

    def attrs(self) -> set[str]:
        return set().union(*(o.attrs() for o in self.operands))

    def eval(self, values: dict[str, Any]) -> bool:
        results = (o.eval(values) for o in self.operands)
        return all(results) if self.op == "&&" else any(results)

    def __str__(self) -> str:
        parts = [f"({o})" if isinstance(o, BoolOp) else str(o) for o in self.operands]
        return f" {self.op} ".join(parts)


Node = Union[Compare, Not, BoolOp]

_TOKEN_RE = re.compile(
    r"(?P<op>==|!=|<=|>=|&&|\|\||[<>!()])"
    r"|(?P<string>\"[^\"]*\"|'[^']*')"
    r"|(?P<number>\d+(?:\s*(?:KiB|MiB|GiB))?)"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)


@dataclass
class _Token:
    kind: str  # op, string, number, name or end
    text: str
    col: int  # 1-based


def _tokenize(text: str) -> list[_Token]:
    tokens = []
    pos = 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos == len(text):
            tokens.append(_Token("end", "", pos + 1))
            return tokens
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ConfError(f'unexpected "{text[pos]}" at column {pos + 1}')
        tokens.append(_Token(m.lastgroup, m.group(), pos + 1))
        pos = m.end()


class _Parser:
    """Recursive-descent parser for a relation condition.

    expr    := and ('||' and)*
    and     := unary ('&&' unary)*
    unary   := '!' unary | '(' expr ')' | compare
    compare := NAME op LITERAL     op: == != < <= > >=
    """

    def __init__(self, text: str, attributes: dict[str, Attribute]):
        self.tokens = _tokenize(text)
        self.i = 0
        self.attributes = attributes

    def parse(self) -> Node:
        node = self._expr()
        tok = self._peek()
        if tok.kind != "end":
            raise self._error(tok, "expected && or || or the end")
        return node

    def _peek(self) -> _Token:
        return self.tokens[self.i]

    def _take(self) -> _Token:
        tok = self.tokens[self.i]
        if tok.kind != "end":
            self.i += 1
        return tok

    def _is_op(self, text: str) -> bool:
        tok = self._peek()
        return tok.kind == "op" and tok.text == text

    @staticmethod
    def _error(tok: _Token, message: str) -> ConfError:
        found = "the end" if tok.kind == "end" else f'"{tok.text}" at column {tok.col}'
        return ConfError(f"{message}, found {found}")

    def _expr(self) -> Node:
        return self._bool("||", self._and)

    def _and(self) -> Node:
        return self._bool("&&", self._unary)

    def _bool(self, op: str, operand) -> Node:
        operands = [operand()]
        while self._is_op(op):
            self._take()
            operands.append(operand())
        return operands[0] if len(operands) == 1 else BoolOp(op, operands)

    def _unary(self) -> Node:
        if self._is_op("!"):
            self._take()
            return Not(self._unary())
        if self._is_op("("):
            self._take()
            node = self._expr()
            if not self._is_op(")"):
                raise self._error(self._peek(), "expected )")
            self._take()
            return node
        return self._compare()

    def _compare(self) -> Node:
        tok = self._take()
        if tok.kind != "name":
            raise self._error(tok, "expected an attribute name")
        if tok.text == SDKCONFIG:
            raise ConfError(f"{SDKCONFIG} cannot be used in a condition")
        attr = self.attributes.get(tok.text)
        if attr is None:
            raise ConfError(f'unknown attribute "{tok.text}" at column {tok.col}')

        op = self._take()
        if op.kind != "op" or op.text not in _COMPARE:
            raise self._error(op, f"expected a comparison after {attr.name}")
        if op.text in _ORDERING and attr.type != "size":
            raise ConfError(f"{op.text} needs a size attribute, {attr.name} is a {attr.type}")

        lit = self._take()
        if attr.type == "string":
            if lit.kind != "string":
                raise self._error(lit, f"expected a quoted string after {attr.name} {op.text}")
            raw = lit.text[1:-1]
        else:
            if lit.kind != "number":
                raise self._error(lit, f"expected a size such as 8MiB after {attr.name} {op.text}")
            raw = lit.text
        # == and != also check the enum, so a typo fails at load time.
        value = attr.normalize(raw) if op.text in ("==", "!=") else attr.convert(raw)
        return Compare(attr, op.text, value)


def parse_condition(text: str, attributes: dict[str, Attribute]) -> Node:
    return _Parser(text, attributes).parse()


# --- Relations and model ---------------------------------------------------


@dataclass
class Relation:
    index: int
    if_text: str | None
    condition: Node | None
    sets: dict[str, Any]
    sdkconfig: list[str]

    @property
    def name(self) -> str:
        if self.if_text is None:
            return f"relations[{self.index}]"
        return f"relations[{self.index}] (if {self.if_text})"

    def reads(self) -> set[str]:
        return self.condition.attrs() if self.condition is not None else set()

    def targets(self) -> list[str]:
        return list(self.sets) + ([SDKCONFIG] if self.sdkconfig else [])

    def applies(self, values: dict[str, Any]) -> bool:
        return self.condition is None or self.condition.eval(values)


@dataclass
class Model:
    path: str
    attributes: dict[str, Attribute]
    relations: list[Relation]
    format_version: str | None = None


def read_yaml(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except OSError as e:
        raise ConfError(f"{path}: {e.strerror}") from None
    except yaml.YAMLError as e:
        raise ConfError(f"{path}: {e}") from None


def _pairs(node: Any, what: str) -> list[tuple[Any, Any]]:
    """Read a map, or a list of single-key maps, as (key, value) pairs."""
    if isinstance(node, dict):
        return list(node.items())
    if isinstance(node, list):
        pairs = []
        for i, item in enumerate(node):
            if not isinstance(item, dict) or len(item) != 1:
                raise ConfError(f"{what}[{i}]: expected one 'name: value' entry")
            pairs.extend(item.items())
        return pairs
    raise ConfError(f"{what}: expected a map or a list of 'name: value' entries")


def _parse_attributes(node: Any) -> dict[str, Attribute]:
    attributes: dict[str, Attribute] = {}
    for name, spec in _pairs(node, "attributes"):
        with _where(f"attributes: {name}"):
            if not isinstance(name, str) or not _NAME_RE.match(name):
                raise ConfError("not a valid attribute name")
            if name == SDKCONFIG:
                raise ConfError(f"{SDKCONFIG} is intrinsic, it cannot be declared")
            if name in attributes:
                raise ConfError("declared twice")
            if not isinstance(spec, dict):
                raise ConfError("expected a map with type and enum")
            unknown = set(spec) - {"type", "enum"}
            if unknown:
                raise ConfError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
            if spec.get("type") not in TYPES:
                raise ConfError(f"type must be one of: {', '.join(TYPES)}")
            attr = Attribute(name, spec["type"])
            if "enum" in spec:
                enum = spec["enum"]
                if not isinstance(enum, list) or not enum:
                    raise ConfError("enum must be a list with one or more values")
                attr.enum = [attr.convert(v) for v in enum]
            attributes[name] = attr
    return attributes


def _parse_sdkconfig(node: Any) -> list[str]:
    if isinstance(node, str):
        chunks = [node]
    elif isinstance(node, list) and all(isinstance(x, str) for x in node):
        chunks = node
    else:
        raise ConfError(f"{SDKCONFIG} must be a text block or a list of lines")
    return [line.strip() for chunk in chunks for line in chunk.splitlines() if line.strip()]


def _parse_relation(index: int, node: Any, attributes: dict[str, Attribute]) -> Relation:
    if not isinstance(node, dict):
        raise ConfError(f"relations[{index}]: expected a map with if, then and {SDKCONFIG}")
    if_text = node.get("if")
    location = f"relations[{index}]"
    if isinstance(if_text, str):
        location += f" (if {if_text})"

    with _where(location):
        unknown = set(node) - {"if", "then", SDKCONFIG}
        if unknown:
            raise ConfError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")

        condition = None
        if "if" in node:
            if not isinstance(if_text, str) or not if_text.strip():
                raise ConfError("if must be a condition text")
            condition = parse_condition(if_text, attributes)

        sets: dict[str, Any] = {}
        if "then" in node:
            for name, raw in _pairs(node["then"], "then"):
                if name == SDKCONFIG:
                    raise ConfError(f"then: use the {SDKCONFIG} key to add {SDKCONFIG} lines")
                attr = attributes.get(name)
                if attr is None:
                    raise ConfError(f'then: unknown attribute "{name}"')
                if name in sets:
                    raise ConfError(f"then: {name} is set twice")
                if raw is None:
                    raise ConfError(f"then: {name} has no value")
                sets[name] = attr.normalize(raw)

        lines = _parse_sdkconfig(node[SDKCONFIG]) if SDKCONFIG in node else []
        if not sets and not lines:
            raise ConfError(f"the relation sets nothing (add then or {SDKCONFIG})")

    return Relation(index, if_text, condition, sets, lines)


def load(path: str) -> Model:
    """Read and check the master configuration."""
    data = read_yaml(path)
    with _where(path):
        if not isinstance(data, dict):
            raise ConfError("expected a map with attributes and relations")
        unknown = set(data) - {"format_version", "attributes", "relations"}
        if unknown:
            raise ConfError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
        format_version = None
        if "format_version" in data:
            raw = data["format_version"]
            format_version = str(raw) if isinstance(raw, (str, int, float)) and not isinstance(raw, bool) else None
            if format_version not in FORMAT_VERSIONS:
                supported = ", ".join(f'"{v}"' for v in FORMAT_VERSIONS)
                raise ConfError(f"format_version {raw!r} is not supported (supported: {supported})")
        if "attributes" not in data:
            raise ConfError("attributes is missing")
        attributes = _parse_attributes(data["attributes"])
        relations_node = data.get("relations") or []
        if not isinstance(relations_node, list):
            raise ConfError("relations must be a list")
        relations = [_parse_relation(i, n, attributes) for i, n in enumerate(relations_node)]
    return Model(path, attributes, relations, format_version)


def load_values(model: Model, path: str) -> dict[str, Any]:
    """Read a values file: a map (or list of single-key maps) name -> value.

    An empty value leaves the attribute undefined.
    """
    data = read_yaml(path)
    values: dict[str, Any] = {}
    if data is None:
        return values
    seen: set[str] = set()
    with _where(path):
        for name, raw in _pairs(data, "values"):
            if name == SDKCONFIG:
                raise ConfError(f"{SDKCONFIG} cannot be given in a values file")
            attr = model.attributes.get(name)
            if attr is None:
                raise ConfError(f'unknown attribute "{name}"')
            if name in seen:
                raise ConfError(f"{name} is given twice")
            seen.add(name)
            if raw is not None:
                values[name] = attr.normalize(raw)
    return values


def parse_assignments(model: Model, items: list[str]) -> dict[str, Any]:
    """Read NAME=VALUE arguments from the command line.

    An empty value (NAME=) gives None: the attribute is undefined, also when
    a values file gives it.
    """
    values: dict[str, Any] = {}
    for item in items:
        name, sep, raw = item.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ConfError(f'{COMMAND_LINE}: "{item}": expected NAME=VALUE (use --values FILE for a values file)')
        with _where(f"{COMMAND_LINE}: {item}"):
            if name == SDKCONFIG:
                raise ConfError(f"{SDKCONFIG} cannot be given on the command line")
            attr = model.attributes.get(name)
            if attr is None:
                raise ConfError(f'unknown attribute "{name}"')
            if name in values:
                raise ConfError(f"{name} is given twice")
            raw = raw.strip()
            values[name] = attr.normalize(raw) if raw else None
    return values


# --- Graph and solver ------------------------------------------------------


def build_graph(model: Model) -> dict[str, list[str]]:
    """Map each node (attributes + sdkconfig) to the attributes it depends on.

    A node depends on each attribute in the condition of a relation that sets
    it. The dependency lists follow the declaration order.
    """
    rank = {name: i for i, name in enumerate(model.attributes)}
    deps: dict[str, set[str]] = {name: set() for name in model.attributes}
    deps[SDKCONFIG] = set()
    for rel in model.relations:
        reads = rel.reads()
        for target in rel.targets():
            deps[target] |= reads
    return {node: sorted(d, key=rank.__getitem__) for node, d in deps.items()}


def topo_order(graph: dict[str, list[str]]) -> list[str]:
    """Return the nodes so that each node comes after its dependencies."""
    try:
        return list(graphlib.TopologicalSorter(graph).static_order())
    except graphlib.CycleError as e:
        cycle = e.args[1]
        raise ConfError(f"dependency cycle: {' -> '.join(cycle)}") from None


@dataclass
class Solution:
    values: dict[str, Any]  # None = undefined
    sources: dict[str, str]  # who set each defined attribute
    sdkconfig: list[str]
    applied: list[Relation]  # relations with a true condition, file order


def evaluate(
    model: Model,
    graph: dict[str, list[str]],
    inputs: dict[str, Any],
    input_sources: dict[str, str] | None = None,
) -> Solution:
    """Apply the relations to the input values, in dependency order.

    input_sources tells where each input value comes from (for the messages).
    """
    rank = {node: i for i, node in enumerate(topo_order(graph))}
    values: dict[str, Any] = {name: None for name in model.attributes}
    sources: dict[str, str] = {}
    for name, value in inputs.items():
        values[name] = value
        sources[name] = (input_sources or {}).get(name, "input")

    # A relation is evaluated at the first of its targets in the graph order.
    # All the attributes in its condition come before, so they are final.
    applied = []
    for rel in sorted(model.relations, key=lambda r: min(rank[t] for t in r.targets())):
        if not rel.applies(values):
            continue
        applied.append(rel)
        for name, value in rel.sets.items():
            current = values[name]
            if current is None:
                values[name] = value
                sources[name] = rel.name
            elif current != value:
                attr = model.attributes[name]
                raise ConfError(
                    f"conflict on {name}: {rel.name} sets {attr.format(value)}, "
                    f"but {sources[name]} set {attr.format(current)}"
                )

    applied.sort(key=lambda r: r.index)
    lines = [line for rel in applied for line in rel.sdkconfig]
    return Solution(values, sources, lines, applied)


def sdkconfig_requirements(graph: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return the attributes that the sdkconfig lines need: {name: ["sdkconfig"]}."""
    return {name: [SDKCONFIG] for name in graph[SDKCONFIG]}


@dataclass
class Missing:
    needed_by: list[str]  # what needs the attribute
    set_by: list[str]  # attributes whose relations can set it


def find_missing(
    graph: dict[str, list[str]], values: dict[str, Any], required: dict[str, list[str]]
) -> dict[str, Missing]:
    """Return each required attribute that is still undefined, in graph order.

    Only the required attributes count. When a required attribute is defined,
    the attributes that it depends on are not needed.
    """
    missing = {}
    for name in topo_order(graph):
        if name in required and values.get(name) is None:
            missing[name] = Missing(required[name], graph[name])
    return missing
