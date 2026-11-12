"""Configurator model: attributes, rules, dependency graph and solver.

The master configuration (master_config.yaml, in the repository root) has
two parts that this code reads. A third part, "display", tells the Wendy CLI
how to ask the questions (titles, labels, order). This code accepts it and
ignores it; the Go configurator (go/internal/cli/litebuild in WendyOS) reads
it.

attributes
    A map from each name to a type ("string", "size" or "boolean") and an
    optional enum of allowed values (not for a boolean). A size is an integer
    number of bytes; the YAML can write it with a KiB, MiB or GiB unit. A
    boolean is true or false. An attribute can be undefined.

rules
    A list. Each item has an optional "if" condition, a "set" map of
    attribute values and/or a "sdkconfig" text block. When the condition is
    true, the rule sets the attributes and appends the lines to the
    intrinsic "sdkconfig" attribute.

    A chain is an "if" rule, then zero or more "else-if" rules, then
    an optional "else" rule (written "else:" alone), as consecutive
    items. An "else-if" or "else" rule applies only when all the earlier
    conditions of its chain are false. At load time, it gets the full
    condition: "else-if C" after "if A" is "!A && C", "else" is "!A".

    "valid: false" (with a condition, no "set" and no "sdkconfig") marks the
    condition as a combination that is not allowed. When its condition is
    true after the solve, the solution is not allowed.

An attribute depends on each attribute in the condition of a rule that
sets it. The solver evaluates the rules in the order of this graph.
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
DISPLAY = "display"  # top-level section for the Wendy CLI questions, not read here
TYPES = ("string", "size", "boolean")
FORMAT_VERSIONS = ("1.0",)  # format_version values that this code reads
VALUES_FILE = "values file"
COMMAND_LINE = "command line"
# Kconfig option (components/wendy_core/Kconfig) with the input values.
BUILD_PROFILE = "CONFIG_WENDY_BUILD_PROFILE"

_SIZE_UNITS = {"KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}
_SIZE_RE = re.compile(r"^\s*(\d+)\s*(KiB|MiB|GiB)?\s*$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Boolean texts (command line, values file). Conditions use only true and false.
_TRUE_TEXTS = {"true", "yes", "on", "1"}
_FALSE_TEXTS = {"false", "no", "off", "0"}
_BOOL_LITERALS = {"true": True, "false": False}


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


def parse_bool(raw: Any) -> bool:
    """Return a boolean. Accept a YAML boolean, 0/1, or true/false, yes/no, on/off."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int) and raw in (0, 1):
        return bool(raw)
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in _TRUE_TEXTS:
            return True
        if text in _FALSE_TEXTS:
            return False
    raise ConfError(f"{raw!r} is not a boolean (use true or false)")


@dataclass
class Attribute:
    name: str
    type: str
    enum: list[Any] | None = None

    def convert(self, raw: Any) -> Any:
        """Convert a YAML value to the attribute type. No enum check."""
        if self.type == "size":
            return parse_size(raw)
        if self.type == "boolean":
            return parse_bool(raw)
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
        if self.type == "boolean":
            return "true" if value else "false"
        return str(value)

    def to_yaml(self, value: Any) -> Any:
        """Return the value for a values file: convert() accepts it again.

        A size gets the largest unit that divides it ("8MiB"), else it stays
        a number of bytes.
        """
        if self.type == "size":
            for unit in ("GiB", "MiB", "KiB"):
                mult = _SIZE_UNITS[unit]
                if value and value % mult == 0:
                    return f"{value // mult}{unit}"
        return value


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
        literal = f'"{self.value}"' if self.attr.type == "string" else self.attr.format(self.value)
        return f"{self.attr.name} {self.op} {literal}"


@dataclass
class BoolTest:
    """A boolean attribute alone in a condition: true only if the value is true."""

    attr: Attribute

    def attrs(self) -> set[str]:
        return {self.attr.name}

    def eval(self, values: dict[str, Any]) -> bool:
        return values.get(self.attr.name) is True

    def __str__(self) -> str:
        return self.attr.name


@dataclass
class Not:
    operand: Node

    def attrs(self) -> set[str]:
        return self.operand.attrs()

    def eval(self, values: dict[str, Any]) -> bool:
        return not self.operand.eval(values)

    def __str__(self) -> str:
        if isinstance(self.operand, (Not, BoolTest)):
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


Node = Union[Compare, BoolTest, Not, BoolOp]

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
    """Recursive-descent parser for a rule condition.

    expr    := and ('||' and)*
    and     := unary ('&&' unary)*
    unary   := '!' unary | '(' expr ')' | compare
    compare := NAME op LITERAL     op: == != < <= > >=
             | NAME                a boolean attribute alone
    LITERAL := "string" | size such as 8MiB | true | false
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

        nxt = self._peek()
        if attr.type == "boolean" and not (nxt.kind == "op" and nxt.text in _COMPARE):
            return BoolTest(attr)

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
        elif attr.type == "boolean":
            if lit.kind != "name" or lit.text not in _BOOL_LITERALS:
                raise self._error(lit, f"expected true or false after {attr.name} {op.text}")
            raw = _BOOL_LITERALS[lit.text]
        else:
            if lit.kind != "number":
                raise self._error(lit, f"expected a size such as 8MiB after {attr.name} {op.text}")
            raw = lit.text
        # == and != also check the enum, so a typo fails at load time.
        value = attr.normalize(raw) if op.text in ("==", "!=") else attr.convert(raw)
        return Compare(attr, op.text, value)


def parse_condition(text: str, attributes: dict[str, Attribute]) -> Node:
    return _Parser(text, attributes).parse()


# --- Rules and model -------------------------------------------------------


_KEYWORDS = ("if", "else-if", "else")


def _rule_name(index: int, keyword: str | None, text: Any) -> str:
    name = f"rules[{index}]"
    if keyword == "else":
        return f"{name} (else)"
    if keyword is not None and isinstance(text, str):
        return f"{name} ({keyword} {text})"
    return name


@dataclass
class Rule:
    index: int
    keyword: str | None  # "if", "else-if", "else", or None (no condition)
    if_text: str | None  # the condition text as written (None for else)
    condition: Node | None  # for else-if and else, it includes the chain
    sets: dict[str, Any]
    sdkconfig: list[str]
    forbidden: bool = False  # valid: false: the condition is not allowed

    @property
    def name(self) -> str:
        return _rule_name(self.index, self.keyword, self.if_text)

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
    rules: list[Rule]
    format_version: str | None = None


class _UniqueKeyLoader(yaml.SafeLoader):
    """A safe YAML loader that rejects a key given twice in one map."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:  # an unhashable key: the base class reports it
                continue
            if duplicate:
                raise yaml.constructor.ConstructorError(None, None, f"{key!r} is given twice", key_node.start_mark)
        return super().construct_mapping(node, deep)


def read_yaml(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.load(f, Loader=_UniqueKeyLoader)
    except OSError as e:
        raise ConfError(f"{path}: {e.strerror}") from None
    except yaml.YAMLError as e:
        raise ConfError(f"{path}: {e}") from None


def _parse_attributes(node: Any) -> dict[str, Attribute]:
    if not isinstance(node, dict):
        raise ConfError("attributes must be a map of 'name: {type, enum}' entries")
    attributes: dict[str, Attribute] = {}
    for name, spec in node.items():
        with _where(f"attributes: {name}"):
            if not isinstance(name, str) or not _NAME_RE.match(name):
                raise ConfError("not a valid attribute name")
            if name == SDKCONFIG:
                raise ConfError(f"{SDKCONFIG} is intrinsic, it cannot be declared")
            if name in _BOOL_LITERALS:
                raise ConfError(f"{name} is a reserved word")
            if not isinstance(spec, dict):
                raise ConfError("expected a map with type and enum")
            unknown = set(spec) - {"type", "enum"}
            if unknown:
                raise ConfError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
            if spec.get("type") not in TYPES:
                raise ConfError(f"type must be one of: {', '.join(TYPES)}")
            attr = Attribute(name, spec["type"])
            if "enum" in spec and attr.type == "boolean":
                raise ConfError("a boolean has no enum")
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


def _all(operands: list[Node]) -> Node:
    return operands[0] if len(operands) == 1 else BoolOp("&&", operands)


def _parse_rule(
    index: int, node: Any, attributes: dict[str, Attribute], chain: list[Node] | None
) -> tuple[Rule, list[Node] | None]:
    """Read one rule.

    chain holds the conditions of the open if/else-if chain, or None when no
    chain is open. Return the rule and the chain after it.
    """
    if not isinstance(node, dict):
        raise ConfError(f"rules[{index}]: expected a map with if, else-if or else, set, {SDKCONFIG} or valid")
    keywords = [k for k in _KEYWORDS if k in node]
    keyword = keywords[0] if keywords else None
    if_text = node.get(keyword) if keyword in ("if", "else-if") else None

    with _where(_rule_name(index, keyword, if_text)):
        unknown = set(node) - {*_KEYWORDS, "set", SDKCONFIG, "valid"}
        if unknown:
            raise ConfError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
        if len(keywords) > 1:
            raise ConfError("use only one of if, else-if and else")
        if keyword in ("else-if", "else") and chain is None:
            raise ConfError(f"{keyword} must follow an if or else-if rule")

        condition: Node | None = None
        new_chain: list[Node] | None = None
        if keyword in ("if", "else-if"):
            if not isinstance(if_text, str) or not if_text.strip():
                raise ConfError(f"{keyword} must be a condition text")
            own = parse_condition(if_text, attributes)
            if keyword == "if":
                condition, new_chain = own, [own]
            else:
                assert chain is not None
                condition, new_chain = _all([*(Not(c) for c in chain), own]), [*chain, own]
        elif keyword == "else":
            if node["else"] is not None:
                raise ConfError("else takes no condition (write else: alone, or use else-if)")
            assert chain is not None
            condition = _all([Not(c) for c in chain])

        if "valid" in node:
            if node["valid"] is not False:
                raise ConfError("valid must be false (leave it out for an allowed combination)")
            if condition is None:
                raise ConfError("valid: false needs an if, else-if or else")
            if "set" in node or SDKCONFIG in node:
                raise ConfError(f"valid: false cannot have set or {SDKCONFIG}")
            return Rule(index, keyword, if_text, condition, {}, [], forbidden=True), new_chain

        values = node.get("set", {})
        if not isinstance(values, dict):
            raise ConfError("set must be a map of 'name: value' entries")

        sets: dict[str, Any] = {}
        for name, raw in values.items():
            if name == SDKCONFIG:
                raise ConfError(f"set: use the {SDKCONFIG} key to add {SDKCONFIG} lines")
            attr = attributes.get(name)
            if attr is None:
                raise ConfError(f'set: unknown attribute "{name}"')
            if raw is None:
                raise ConfError(f"set: {name} has no value")
            sets[name] = attr.normalize(raw)

        lines = _parse_sdkconfig(node[SDKCONFIG]) if SDKCONFIG in node else []
        if not sets and not lines:
            raise ConfError(f"the rule sets nothing (add set or {SDKCONFIG})")

    return Rule(index, keyword, if_text, condition, sets, lines), new_chain


def load(path: str) -> Model:
    """Read and check the master configuration."""
    data = read_yaml(path)
    with _where(path):
        if not isinstance(data, dict):
            raise ConfError("expected a map with attributes and rules")
        # display: how the Wendy CLI asks the questions. The solver ignores it.
        unknown = set(data) - {"format_version", "attributes", "rules", DISPLAY}
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
        rules_node = data.get("rules") or []
        if not isinstance(rules_node, list):
            raise ConfError("rules must be a list")
        rules: list[Rule] = []
        chain: list[Node] | None = None
        for i, n in enumerate(rules_node):
            rule, chain = _parse_rule(i, n, attributes, chain)
            rules.append(rule)
    return Model(path, attributes, rules, format_version)


def load_values(model: Model, path: str) -> dict[str, Any]:
    """Read a values file: a map name -> value.

    An empty value leaves the attribute undefined.
    """
    data = read_yaml(path)
    values: dict[str, Any] = {}
    if data is None:
        return values
    with _where(path):
        if not isinstance(data, dict):
            raise ConfError("expected a map of 'name: value' entries")
        for name, raw in data.items():
            if name == SDKCONFIG:
                raise ConfError(f"{SDKCONFIG} cannot be given in a values file")
            attr = model.attributes.get(name)
            if attr is None:
                raise ConfError(f'unknown attribute "{name}"')
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


def build_profile(model: Model, inputs: dict[str, Any]) -> str:
    """Return the input values as flat YAML, one "name: value" per line.

    The lines follow the declaration order, so the order of the arguments
    does not change the text. The text is a valid values file. No inputs
    give "".
    """
    data = {name: attr.to_yaml(inputs[name]) for name, attr in model.attributes.items() if name in inputs}
    if not data:
        return ""
    text = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=1_000_000)
    return text.rstrip("\n")


def kconfig_string_line(option: str, value: str) -> str:
    r"""Return the sdkconfig line that gives the string value to option.

    The value is escaped as Kconfig does (kconfiglib _escape): \ becomes \\,
    then " becomes \".
    """
    value = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{option}="{value}"'


def build_profile_line(text: str) -> str:
    r"""Return the sdkconfig line that gives text to BUILD_PROFILE.

    Kconfig cannot store a newline, so each newline becomes the 2 characters
    \n (backslash, n). Then kconfig_string_line() escapes the value.
    """
    return kconfig_string_line(BUILD_PROFILE, text.replace("\n", "\\n"))


# --- Graph and solver ------------------------------------------------------


def build_graph(model: Model) -> dict[str, list[str]]:
    """Map each node (attributes + sdkconfig) to the attributes it depends on.

    A node depends on each attribute in the condition of a rule that sets
    it. The dependency lists follow the declaration order.
    """
    rank = {name: i for i, name in enumerate(model.attributes)}
    deps: dict[str, set[str]] = {name: set() for name in model.attributes}
    deps[SDKCONFIG] = set()
    for rule in model.rules:
        reads = rule.reads()
        for target in rule.targets():
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
    applied: list[Rule]  # rules with a true condition, file order
    forbidden: list[Rule]  # valid: false rules with a true condition, file order

    @property
    def allowed(self) -> bool:
        """True when no valid: false rule matches the solved values."""
        return not self.forbidden


def not_allowed_text(rules: list[Rule]) -> str:
    """Return the error text for the valid: false rules that match."""
    return "not allowed: " + "; ".join(rule.name for rule in rules)


def evaluate(
    model: Model,
    graph: dict[str, list[str]],
    inputs: dict[str, Any],
    input_sources: dict[str, str] | None = None,
) -> Solution:
    """Apply the rules to the input values, in dependency order.

    input_sources tells where each input value comes from (for the messages).
    """
    rank = {node: i for i, node in enumerate(topo_order(graph))}
    values: dict[str, Any] = {name: None for name in model.attributes}
    sources: dict[str, str] = {}
    for name, value in inputs.items():
        values[name] = value
        sources[name] = (input_sources or {}).get(name, "input")

    # A rule is evaluated at the first of its targets in the graph order.
    # All the attributes in its condition come before, so they are final.
    # A valid: false rule has no target: it is evaluated after the loop.
    setters = [rule for rule in model.rules if not rule.forbidden]
    applied = []
    for rule in sorted(setters, key=lambda r: min(rank[t] for t in r.targets())):
        if not rule.applies(values):
            continue
        applied.append(rule)
        for name, value in rule.sets.items():
            current = values[name]
            if current is None:
                values[name] = value
                sources[name] = rule.name
            elif current != value:
                attr = model.attributes[name]
                raise ConfError(
                    f"conflict on {name}: {rule.name} sets {attr.format(value)}, "
                    f"but {sources[name]} set {attr.format(current)}"
                )

    # A value never changes after it is set, so these are the final values.
    forbidden = [rule for rule in model.rules if rule.forbidden and rule.applies(values)]

    applied.sort(key=lambda r: r.index)
    lines = [line for rule in applied for line in rule.sdkconfig]
    return Solution(values, sources, lines, applied, forbidden)


def sdkconfig_requirements(graph: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return the attributes that the sdkconfig lines need: {name: ["sdkconfig"]}."""
    return {name: [SDKCONFIG] for name in graph[SDKCONFIG]}


@dataclass
class Missing:
    needed_by: list[str]  # what needs the attribute
    set_by: list[str]  # attributes whose rules can set it


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
