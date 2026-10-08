---
name: role-subjects-membership-bypass
description: Group/role membership bypass via direct role-subjects manipulation. Many apps model memberships as a role object holding a 'subjects' array of user IDs. Instead of (or in addition to) the invite+accept+remove flow, the update-role endpoint writes the subjects array directly — so you can add ANY user ID to the group without an invitation or acceptance, and remove members (or lock them in) without authorization. Exploits: membership added with no invite/consent, forced indefinite membership (victim can't leave), unauthorized removal, privilege inclusion in a trusted group. Triggers on: PUT/PATCH /api/roles/{id} with a 'subjects' array, add member to group without invite, force user into a team/company, membership authorization bypass, org user-role manipulation.
---

# Role-Subjects Membership Bypass (add any user to a group without invite, lock them in)

A clean broken-access-control / business-logic bug in apps that model group
membership as a **role object whose `subjects` array is the member list**. The
invite/accept/remove flow is a UX layer on top of that array. If the update-role
endpoint lets you write `subjects` directly, you can mutate membership with no
invitation, no acceptance, and — if there's no authorization check — as any user.

## How the data model works

Each group/company has roles (admin, support, developer, view-only). Membership is
the `subjects: [user_id, ...]` array on each role:

```json
PUT /api/roles/<view_only_role_id>
{ "name": "View only", "subjects": [<user_id>] }   // user is in the group
{ "name": "View only", "subjects": [] }             // user is OUT of the group
```

The `<role_id>` belongs to a specific group/company. The UI does invite → user
accepts → backend appends the user id to `subjects`. Remove = splice it out.

## The bug (the 3 questions to ask)

1. **Can I add a user ID that isn't in my company, without an invite/accept?**
   ```
   PUT /api/roles/<view_only_role_id>
   { "name": "View only", "subjects": [<victim_user_id>] }
   ```
   If the backend writes the array as-is (no check that the user was invited +
   accepted, no authorization that you can manage membership) → the victim is
   **added to the group with no consent**.

2. **Can they leave?** If there is no self-remove path, or removing requires the
   controller to splice their id out (which the victim can't do for themselves),
   the victim is **locked into the group indefinitely**. Impact: forced membership
   in a money/member company, exposure to the group's data/actions.

3. **Can I remove others (esp. admins) or reassign roles?** Same primitive →
   privilege manipulation: demote an admin by moving their id to a lower role's
   subjects, or empty the admin role.

## Reusable cases / where this pattern appears

Any product with shared workspaces / groups / orgs / teams / partners modeled as
role→subjects:

- Put a **victim user ID into a group they don't belong to** (no invite/accept).
- **Lock a user in** (they can't leave; no self-remove, or removal requires the
  controller).
- **Remove/demote a privileged member** (empty an admin role's subjects, or move a
  user from admin→view-only) — especially cross-privilege (a customer/support adding
  or demoting an admin).
- **Force membership into a trusted/paid/limited group** to gain entitlements.

## Methodical checklist

1. Map the invite/accept/remove flow; capture the exact update-role requests
   (note the role ids and the subjects array).
2. Enumerate a real user ID in a **different** group/company (or a non-member).
3. Send `PUT /api/roles/<your_role_id>` with that foreign user's ID in `subjects`.
   - Does it succeed? Does the victim now appear in your group's member list?
4. Check authorization: can a **low-privilege** user (support/view-only) do this, or
   only admins? If any member can mutate `subjects` → broken access control.
5. Check the **leave path**: can the added victim remove themselves? If not → forced
   membership.
6. Check **removal path**: can you remove/demote a higher-privilege member (admin)?

## Reporting
- Classify as **broken access control / authorization** (IDOR-adjacent: object/role
  manipulation) or **business-logic** membership bypass.
- Impact: unauthorized addition to a (possibly money-moving/private/trusted) group,
  forced membership without consent, entitlement/privilege inclusion, or removal/
  demotion of privileged members.
- Include: the exact `PUT /api/roles/{role_id}` with a foreign user id in subjects,
  the result (member list shows the victim), and that no invite/accept was involved.
- Root cause: the update-role endpoint trusts the client-supplied `subjects` array
  without (a) verifying the listed users were invited/accepted, and (b) enforcing
  the caller's authorization to manage that membership. Fix = server-side validation
  that subjects only contain authorized, consensual members + enforce role-edit authz.

## Gotchas
- The `subjects` array may be read-only for the role in some apps (only invite flow
  appends) — then the primitive is different (see "invite flow" variants). Test
  whether update-role accepts arbitrary ids.
- Ensure you add/remove only **owned/authorized test accounts** and clean up (remove
  the victim id from subjects) after confirming.
- If the victim user id must exist app-wide but not in the group, craft the request
  with a valid user id from another group you control — never target real
  third-party members.
- Some apps re-sync subjects from the invite table on read; verify the change
  actually persists and shows in the member list (not just an ephemeral write).
