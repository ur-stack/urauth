"""Tests for RelationEnum — declarative Zanzibar relation definitions."""

from __future__ import annotations

import pytest

from urauth.authz.primitives import Relation, RelationTuple
from urauth.authz.relation_enum import RelationEnum

# ── Fixture enum ─────────────────────────────────────────────────


class Rels(RelationEnum):
    DOC_OWNER = "doc#owner"
    DOC_VIEWER = ("doc", "viewer")
    FOLDER_EDITOR = Relation("folder", "editor")


# ── Value construction ───────────────────────────────────────────


def test_string_form_creates_relation() -> None:
    rel = Rels.DOC_OWNER.value
    assert isinstance(rel, Relation)
    assert str(rel.resource) == "doc"
    assert rel.name == "owner"


def test_tuple_form_creates_relation() -> None:
    rel = Rels.DOC_VIEWER.value
    assert isinstance(rel, Relation)
    assert str(rel.resource) == "doc"
    assert rel.name == "viewer"


def test_relation_object_form() -> None:
    rel = Rels.FOLDER_EDITOR.value
    assert isinstance(rel, Relation)
    assert str(rel.resource) == "folder"
    assert rel.name == "editor"


# ── __str__ ──────────────────────────────────────────────────────


def test_str_output_matches_string_form() -> None:
    assert str(Rels.DOC_OWNER) == "doc#owner"


# ── Equality across forms ────────────────────────────────────────


def test_string_form_equals_tuple_form() -> None:
    class A(RelationEnum):
        DOC_OWNER = "doc#owner"

    class B(RelationEnum):
        DOC_OWNER = ("doc", "owner")

    assert A.DOC_OWNER == B.DOC_OWNER


def test_hash_equality_across_forms() -> None:
    class A(RelationEnum):
        DOC_OWNER = "doc#owner"

    class B(RelationEnum):
        DOC_OWNER = ("doc", "owner")

    assert hash(A.DOC_OWNER) == hash(B.DOC_OWNER)


# ── Equality with raw string ────────────────────────────────────


def test_equality_with_raw_string() -> None:
    assert Rels.DOC_OWNER == "doc#owner"


# ── Equality with Relation object ───────────────────────────────


def test_equality_with_relation_object() -> None:
    assert Relation("doc", "owner") == Rels.DOC_OWNER
    assert Relation("doc", "owner") == Rels.DOC_OWNER


# ── Different separators compare equal (semantic) ────────────────


def test_different_separators_compare_equal() -> None:
    assert Rels.DOC_OWNER == "doc.owner"
    assert Rels.DOC_OWNER == "doc#owner"


# ── .tuple() method ─────────────────────────────────────────────


def test_tuple_method_returns_relation_tuple() -> None:
    rt = Rels.DOC_OWNER.tuple("readme", "user:alice")
    assert isinstance(rt, RelationTuple)
    assert str(rt.relation.resource) == "doc"
    assert rt.relation.name == "owner"
    assert rt.object_id == "readme"
    assert rt.subject == "user:alice"


# ── Invalid value raises TypeError ──────────────────────────────


def test_invalid_value_raises_type_error() -> None:
    with pytest.raises(TypeError):

        class Bad(RelationEnum):  # pyright: ignore[reportUnusedClass]
            NOPE = 42  # type: ignore[assignment]


# ── Custom __parser__ ───────────────────────────────────────────


def test_custom_parser() -> None:
    def my_parser(s: str) -> tuple[str, str]:
        parts = s.split("::", 1)
        return parts[0], parts[1]

    class CustomRels(RelationEnum):
        __parser__ = my_parser
        TEAM_MEMBER = "team::member"

    rel = CustomRels.TEAM_MEMBER.value
    assert str(rel.resource) == "team"
    assert rel.name == "member"
