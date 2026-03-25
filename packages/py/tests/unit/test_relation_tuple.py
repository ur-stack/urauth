"""Tests for RelationTuple — full Zanzibar relationship tuples."""

from __future__ import annotations

import pytest

from urauth.authz.primitives import Relation, RelationTuple

# ── Construction ─────────────────────────────────────────────────


def test_construction_with_subject() -> None:
    rt = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    assert str(rt.relation.resource) == "doc"
    assert rt.relation.name == "owner"
    assert rt.object_id == "readme"
    assert rt.subject == "user:alice"


def test_subject_defaults_to_none() -> None:
    rt = RelationTuple(Relation("doc", "owner"), "readme")
    assert rt.subject is None


# ── __str__ ──────────────────────────────────────────────────────


def test_str_with_subject() -> None:
    rt = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    assert str(rt) == "doc:readme#owner@user:alice"


def test_str_without_subject() -> None:
    rt = RelationTuple(Relation("doc", "owner"), "readme")
    assert str(rt) == "doc:readme#owner"


# ── parse() ──────────────────────────────────────────────────────


def test_parse_with_subject() -> None:
    rt = RelationTuple.parse("doc:readme#owner@user:alice")
    assert str(rt.relation.resource) == "doc"
    assert rt.relation.name == "owner"
    assert rt.object_id == "readme"
    assert rt.subject == "user:alice"


def test_parse_without_subject() -> None:
    rt = RelationTuple.parse("doc:readme#owner")
    assert str(rt.relation.resource) == "doc"
    assert rt.relation.name == "owner"
    assert rt.object_id == "readme"
    assert rt.subject is None


def test_parse_with_uuid_object_id() -> None:
    rt = RelationTuple.parse("doc:550e8400-e29b-41d4#owner@user:alice")
    assert str(rt.relation.resource) == "doc"
    assert rt.relation.name == "owner"
    assert rt.object_id == "550e8400-e29b-41d4"
    assert rt.subject == "user:alice"


def test_parse_roundtrip_with_subject() -> None:
    original = "doc:readme#owner@user:alice"
    rt = RelationTuple.parse(original)
    assert str(rt) == original


def test_parse_roundtrip_without_subject() -> None:
    original = "doc:readme#owner"
    rt = RelationTuple.parse(original)
    assert str(rt) == original


# ── Equality ─────────────────────────────────────────────────────


def test_equality_same_data() -> None:
    rt1 = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    rt2 = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    assert rt1 == rt2


def test_equality_with_string() -> None:
    rt = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    assert rt == "doc:readme#owner@user:alice"


# ── Hash ─────────────────────────────────────────────────────────


def test_equal_tuples_have_equal_hashes() -> None:
    rt1 = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    rt2 = RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
    assert hash(rt1) == hash(rt2)


# ── Relation.tuple() shortcut ───────────────────────────────────


def test_relation_tuple_shortcut() -> None:
    rt = Relation("doc", "owner").tuple("readme", "user:alice")
    assert isinstance(rt, RelationTuple)
    assert str(rt) == "doc:readme#owner@user:alice"


# ── Invalid parse ───────────────────────────────────────────────


def test_invalid_parse_raises_value_error() -> None:
    with pytest.raises((ValueError, IndexError)):
        RelationTuple.parse("invalidnocolon")
