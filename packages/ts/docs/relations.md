# Relations

urauth supports [Google Zanzibar](https://research.google/pubs/pub48190/)-style relation tuples for fine-grained, object-level authorization.

## Relation

A `Relation` defines a relationship type between a resource and a subject:

```typescript
import { Relation } from "@urauth/ts";

// Two-arg form (resource, name)
const docOwner = new Relation("doc", "owner");

// Single-string form (auto-detects separator)
const docViewer = new Relation("doc#viewer");
const docEditor = new Relation("doc.editor");

docOwner.resource;    // "doc"
docOwner.name;        // "owner"
docOwner.toString();  // "doc#owner"
```

### Semantic Equality

Like permissions, relation comparison is separator-agnostic:

```typescript
new Relation("doc#owner").equals(new Relation("doc.owner")); // true
new Relation("doc#owner").equals("doc.owner");                // true
```

## RelationTuple

A full Zanzibar tuple binding a relation to a specific object and subject:

```
object_type:object_id#relation@subject
```

### Construction

```typescript
import { Relation, RelationTuple } from "@urauth/ts";

// From a Relation
const docOwner = new Relation("doc", "owner");
const tuple = new RelationTuple(docOwner, "readme", "user:alice");
// Or via shorthand:
const tuple2 = docOwner.tuple("readme", "user:alice");

tuple.toString();  // "doc:readme#owner@user:alice"
```

### Parsing

```typescript
const t = RelationTuple.parse("doc:readme#owner@user:alice");
t.relation.resource;  // "doc"
t.relation.name;      // "owner"
t.objectId;           // "readme"
t.subject;            // "user:alice"
```

### Without Subject

Subject is optional — useful when you only need the object-relation part:

```typescript
const t = new RelationTuple(new Relation("doc", "owner"), "readme");
t.toString();  // "doc:readme#owner"
t.subject;     // undefined
```

## defineRelations

Create a frozen map of named `Relation` instances:

```typescript
import { defineRelations } from "@urauth/ts";

const Rels = defineRelations({
  DOC_OWNER: "doc#owner",              // string form
  DOC_VIEWER: ["doc", "viewer"],        // tuple form
  FOLDER_EDITOR: new Relation("folder", "editor"),  // Relation object
});

Rels.DOC_OWNER.resource;  // "doc"
Rels.DOC_OWNER.name;      // "owner"
Rels.DOC_OWNER.tuple("readme", "user:alice");  // RelationTuple
```

## Checking Relations in AuthContext

```typescript
import { AuthContext, Relation } from "@urauth/ts";

const docOwner = new Relation("doc", "owner");

const ctx = new AuthContext({
  user: { id: "alice" },
  relations: [docOwner.tuple("readme")],
});

ctx.hasRelation(docOwner, "readme");   // true
ctx.hasRelation(docOwner, "other");    // false
```

## Composition

Relations compose with permissions and roles:

```typescript
const canEdit = new Permission("doc", "write");
const isOwner = new Relation("doc", "owner");
const admin = new Role("admin");

// Owner can edit, or admin can do anything
const requirement = isOwner.and(canEdit).or(admin);
ctx.satisfies(requirement);
```
