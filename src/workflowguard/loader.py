from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .models import WorkflowDoc


class WorkflowLoadError(ValueError):
    """A workflow could not be read as safe, unambiguous YAML."""


class GithubSafeLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 boolean behavior for GitHub's `on` key."""


GithubSafeLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for _first, _resolvers in tuple(GithubSafeLoader.yaml_implicit_resolvers.items()):
    GithubSafeLoader.yaml_implicit_resolvers[_first] = [
        (tag, pattern)
        for tag, pattern in _resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
GithubSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def _construct_unknown_tag(loader: GithubSafeLoader, _suffix: str, node: Node) -> Any:
    """Treat GitHub-specific YAML tags as their underlying safe scalar/collection."""
    if isinstance(node, ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, MappingNode):
        return loader.construct_mapping(node, deep=True)
    raise WorkflowLoadError("unsupported YAML node")


GithubSafeLoader.add_multi_constructor("!", _construct_unknown_tag)


def _check_duplicate_keys(node: Node) -> None:
    if isinstance(node, MappingNode):
        keys: set[tuple[str, str]] = set()
        for key_node, value_node in node.value:
            if isinstance(key_node, (ScalarNode, SequenceNode, MappingNode)):
                identity = (key_node.id, str(key_node.value))
                if identity in keys:
                    raise WorkflowLoadError(
                        f"duplicate YAML key {key_node.value!r} at line {key_node.start_mark.line + 1}"
                    )
                keys.add(identity)
            _check_duplicate_keys(value_node)
    elif isinstance(node, SequenceNode):
        for item in node.value:
            _check_duplicate_keys(item)


def _index_lines(node: Node, path: tuple[object, ...], out: dict[tuple[object, ...], int]) -> None:
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, ScalarNode) else str(key_node.value)
            child = path + (key,)
            out[child] = key_node.start_mark.line + 1
            _index_lines(value_node, child, out)
    elif isinstance(node, SequenceNode):
        for index, item in enumerate(node.value):
            _index_lines(item, path + (index,), out)


def load_workflow(path: Path, relative_path: str) -> WorkflowDoc:
    try:
        text = path.read_text(encoding="utf-8")
        node = yaml.compose(text, Loader=GithubSafeLoader)
        if node is None:
            return WorkflowDoc({}, {}, text, relative_path)
        _check_duplicate_keys(node)
        data = yaml.load(text, Loader=GithubSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError, WorkflowLoadError) as exc:
        raise WorkflowLoadError(f"{relative_path}: {exc}") from exc

    line_map: dict[tuple[object, ...], int] = {}
    _index_lines(node, (), line_map)
    return WorkflowDoc(data, line_map, text, relative_path)
