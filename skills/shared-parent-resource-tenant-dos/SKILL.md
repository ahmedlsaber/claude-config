---
name: shared-parent-resource-tenant-dos
description: Tenant/company-wide denial-of-service via deleting or mutating a shared parent/root resource through an IDOR. Multi-tenant apps often nest per-user objects under a company-scoped ROOT resource (e.g. a main folder via _parent_folder_id). A low-privilege standard user can swap an object's own id for the shared parent/root id in a delete (or move/rename/purge) request -> the root is deleted -> the whole tenant breaks (all folders gone) and, in some apps, every account in the company is deactivated (admin + standard users can no longer log in). Impact is company-scoped availability loss, repeatable, and only needs one internal account. Also covers mutating a shared parent id in any mutate endpoint. Triggers on: delete main/root/parent folder kills whole tenant, IDOR delete on _parent_folder_id/root resource, deactivating all team accounts, tenant-wide DoS via shared resource, low-privilege mass-resource deletion.
---

# Tenant-Wide DoS via Shared Parent/Root Resource (IDOR-delete)

In multi-tenant apps, per-user objects (folders, files, documents, workspaces) are
nested under a **company-scoped root/parent resource** (e.g. one main folder that
holds every team member's folders — identified by a `_parent_folder_id`). When a
low-privilege user can **target the shared root by id in a destroy/mutate endpoint**,
deleting it can take down the **entire tenant** — sometimes disabling every account
in the company.

## The pattern

1. Create an object (folder); the create response exposes:
   - `_id` — unique to the object you just created
   - `_parent_folder_id` — the shared main/root folder for the whole team
2. Create a second object → `_id` changes, `_parent_folder_id` is the **same**
   (confirming the parent is company-scoped, not per-user).
3. Intercept a **delete** (or move/rename/purge/empty) request for your object and
   replace `_id` with `_parent_folder_id` (the root).
4. Send it → the **root is deleted**, which cascades:
   - all team folders/files are gone, AND/OR
   - every account in the company (admin + standard) is **deactivated** — subsequent
     logins fail with "email or password is incorrect".

## Why the impact is tenant-wide

Because the deleted resource is the **company root**, not the user's own object, the
destruction is not scoped to the actor: it affects the whole company, including
admins, and can break authentication/activation for all members. It's repeatable
(the root can be re-created and re-deleted) and only requires **one internal/standard
account**.

## Reusable checklist

1. **Find shared/parent resource ids** in create responses (`_parent_folder_id`,
   `parentId`, `rootFolderId`, `workspaceId`, `companyId`) and confirm they're
   constant across your own objects (company-scoped, not per-object).
2. **IDOR the destroy/mutate endpoint**: change your object's id to the shared
   parent/root id and send delete (also try move, rename, empty, export, change-perm).
3. **Confirm the boundary isn't enforced**: does delete/mutate validate that the
   target belongs to the caller, or does it trust the supplied id? Low-privilege
   user targeting the root = broken object-level authorization.
4. **Assess blast radius**: after deletion, can you/the whole company log in? Create
   new objects? Are admins affected? This determines severity.
5. Also test the **write counterparts**: can a low-priv user rename/repurpose/move
   the shared parent (not just delete)?
6. Use ONLY owned/authorized test accounts and **restore the root** afterward (or
   coordinate with the vendor) — a tenant-wide deactivation is destructive.

## Reporting
- Classify as **IDOR / BOLA + improper authorization** leading to a **tenant-wide /
  business-logic DoS** (CWE-639 / CWE-862 / CWE-284). Medium is typical, but if the
  whole company's accounts are disabled with no recovery, it can be High.
- Frame the impact honestly: requires an internal account; scoped to ONE company
  (not cross-tenant); may be a quick restore. But note it's **repeatable** and affects
  admin accounts too.
- Include: the create response showing `_parent_folder_id`, the delete request with
  the id swapped to the parent/root id, and evidence that all accounts (incl. admin)
  can no longer log in.
- Root cause: the delete/mutate endpoint does not verify the target resource belongs
  to the caller (or to the caller's permission scope), so a shared root is deletable
  by any internal user. Fix: enforce per-object ownership / a minimum-privilege check
  on delete, and protect company-root resources from non-admin deletion.

## Gotchas
- Confirm `_parent_folder_id` is truly company-scoped (same across your objects) and
  that deletion of it is not compensated/blocked server-side.
- Demonstrate with a disposable test company; a full tenant-wide deactivation is
  destructive — stop once you've proven logins fail, then restore/coordinate.
- The same parent-id primitive may also enable cross-tenant impact if a user can guess
  another company's root id (often a UUID/sequence) — check whether it's enumerable,
  and stop before touching another company.
