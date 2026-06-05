from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from lxml import etree
except ModuleNotFoundError:
    deps_path = Path(__file__).resolve().parents[1] / ".deps"
    if deps_path.exists():
        sys.path.insert(0, str(deps_path))
    try:
        from lxml import etree
    except ModuleNotFoundError:
        etree = None


@dataclass(frozen=True)
class SchemaStore:
    root: Path
    by_id: dict[str, dict[str, Any]]
    by_name: dict[str, dict[str, Any]]

    @classmethod
    def from_root(cls, root: str | Path) -> "SchemaStore":
        root = Path(root)
        by_id: dict[str, dict[str, Any]] = {}
        by_name: dict[str, dict[str, Any]] = {}
        for path in root.rglob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            by_name[path.name] = schema
            if "$id" in schema:
                by_id[schema["$id"]] = schema
        return cls(root=root, by_id=by_id, by_name=by_name)

    @classmethod
    def default(cls) -> "SchemaStore":
        workspace_root = Path(__file__).resolve().parents[2]
        schema_root = (
            workspace_root
            / "e-voting-libraries/e-voting-libraries-domain/src/main/resources/json-schema"
            / "ch/post/it/evoting/evotinglibraries/domain"
        )
        return cls.from_root(schema_root)

    def get(self, ref: str) -> dict[str, Any]:
        if ref in self.by_id:
            return self.by_id[ref]
        name = ref.rsplit("/", 1)[-1]
        if name in self.by_name:
            return self.by_name[name]
        raise KeyError(f"unknown schema reference {ref}")

    def validate(self, schema_name_or_ref: str, value: Any) -> list[str]:
        schema = self.get(schema_name_or_ref)
        return list(self._iter_errors(schema, value, "$"))

    def _iter_errors(self, schema: dict[str, Any], value: Any, path: str) -> list[str]:
        errors: list[str] = []
        if "$ref" in schema:
            errors.extend(self._iter_errors(self.get(schema["$ref"]), value, path))

        if "type" in schema:
            expected_type = schema["type"]
            if not _matches_type(value, expected_type):
                return [f"{path}: expected {expected_type}, got {_json_type(value)}"]

        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: value {value!r} not in enum {schema['enum']!r}")

        if isinstance(value, dict):
            errors.extend(self._iter_object_errors(schema, value, path))
        elif isinstance(value, list):
            errors.extend(self._iter_array_errors(schema, value, path))
        elif isinstance(value, str):
            pattern = schema.get("pattern")
            if pattern is not None and re.search(pattern, value) is None:
                errors.append(f"{path}: string does not match pattern {pattern!r}")
        elif isinstance(value, int) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if minimum is not None and value < minimum:
                errors.append(f"{path}: {value} < minimum {minimum}")
            if maximum is not None and value > maximum:
                errors.append(f"{path}: {value} > maximum {maximum}")

        return errors

    def _iter_object_errors(self, schema: dict[str, Any], value: dict[str, Any], path: str) -> list[str]:
        errors: list[str] = []
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required property {name!r}")

        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            for name in extra:
                errors.append(f"{path}: unexpected property {name!r}")

        for name, subschema in properties.items():
            if name in value:
                errors.extend(self._iter_errors(subschema, value[name], f"{path}.{name}"))
        return errors

    def _iter_array_errors(self, schema: dict[str, Any], value: list[Any], path: str) -> list[str]:
        errors: list[str] = []
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if min_items is not None and len(value) < min_items:
            errors.append(f"{path}: array length {len(value)} < minItems {min_items}")
        if max_items is not None and len(value) > max_items:
            errors.append(f"{path}: array length {len(value)} > maxItems {max_items}")

        if schema.get("uniqueItems") is True:
            canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(canonical) != len(set(canonical)):
                errors.append(f"{path}: array items are not unique")

        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                errors.extend(self._iter_errors(item_schema, item, f"{path}[{index}]"))
        return errors


def _matches_type(value: Any, expected_type: str | list[str]) -> bool:
    if isinstance(expected_type, list):
        return any(_matches_type(value, item) for item in expected_type)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected_type == "null":
        return value is None
    raise ValueError(f"unsupported JSON schema type {expected_type}")


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


@dataclass(frozen=True)
class XmlSchemaStore:
    root: Path

    @classmethod
    def default(cls) -> "XmlSchemaStore":
        workspace_root = Path(__file__).resolve().parents[2]
        return cls(workspace_root / "e-voting-libraries/e-voting-libraries-xml/src/main/resources/xsd")

    def validate(self, schema_name: str, xml_path: str | Path) -> list[str]:
        if etree is None:
            return ["lxml dependency not installed"]
        schema_path = self.root / schema_name
        if not schema_path.exists():
            return [f"unknown XML schema {schema_name}"]
        parser = etree.XMLParser(resolve_entities=False, no_network=False, huge_tree=True)
        try:
            schema_doc = etree.parse(str(schema_path), parser)
            xml_schema = etree.XMLSchema(schema_doc)
            xml_doc = etree.parse(str(xml_path), parser)
        except (OSError, etree.XMLSyntaxError, etree.XMLSchemaParseError) as exc:
            return [str(exc)]
        if xml_schema.validate(xml_doc):
            return []
        return [f"line {error.line}: {error.message}" for error in xml_schema.error_log[:5]]
