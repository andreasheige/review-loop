# PRD: Document sharing (epic `doc-sharing`)

## Goal

Every document in docs-service is private to its owner today. Teams want to work on documents
together, get back to an earlier version after a bad edit, and show a document to someone who has
no account.

## Scope

1. **Workspaces** (DS-1). A user creates a workspace and adds members as `viewer` or `editor`.
   Documents can be created in a workspace. Viewers read the workspace's documents, editors read
   and edit them, only the owner deletes a document. A document shows who it is shared with
   (name, email, role) so teammates know who sees their changes.
2. **Version history** (DS-2). Every save keeps the previous content. Whoever can read a document
   can list and open its past versions; whoever can edit it can restore one. Restoring is itself
   an edit, so it can be undone.
3. **Share links** (DS-3). The owner creates a read-only link to a document and can revoke it.
   Anyone with the link reads the document without signing in.

Out of scope: real-time editing, comments, link expiry, per-document permissions beyond workspaces.

## Acceptance criteria

- A user who is neither the owner nor a member of the document's workspace cannot read, list,
  edit, restore or see the history of it (404).
- Viewers cannot edit or restore; editors can; only the owner deletes or shares.
- Restoring a version changes the document's title and content, nothing else.
- A revoked share link stops working and stays revoked.
- Share links cannot be guessed or enumerated.
- Someone opening a share link sees the title, content and last-updated time, and nothing about
  the owner or the workspace's members.
