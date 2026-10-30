#!/usr/bin/env bash
# Deterministically build the golden toy epic "doc-sharing" under $1/doc-sharing.
#
# main                      the app before the epic (one commit)
# ticket/DS-1-workspaces    T1, one commit on main
# ticket/DS-2-versions      T2, one commit on main
# ticket/DS-3-share-links   T3, one commit on main
# epic/doc-sharing          main + --no-ff merges of T1, T2, T3 (in that order): the buggy epic
#
# The three tickets were developed in parallel from main and merged into the epic branch,
# so each ticket diff is main..ticket head. Every merge is clean (no textual conflict).
#
# The clean twin fixes the four seeded seam bugs and is otherwise the same:
# ticket/DS-2-versions-clean, ticket/DS-3-share-links-clean   T2/T3 with their ticket-local fixes
# epic/doc-sharing-clean    main + merges of T1, T2-clean, T3-clean; the T2 merge also wires the
#                           version routes to T1's access loader (the one fix only the merge can make)
#
# Fixed identities, dates and an empty global config make the SHAs reproducible.
# $1/doc-sharing must not exist yet. Prints "<name> <sha>" per ref.
set -euo pipefail

out="${1:?usage: build.sh <out-dir>}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME="Golden Fixture" GIT_AUTHOR_EMAIL="fixture@example.invalid"
export GIT_COMMITTER_NAME="Golden Fixture" GIT_COMMITTER_EMAIL="fixture@example.invalid"
export TZ=UTC LC_ALL=C
umask 022

repo="$out/doc-sharing"
if [ -e "$repo" ]; then
  echo "build.sh: $repo already exists, use a fresh directory" >&2
  exit 1
fi
mkdir -p "$repo"
git -c init.defaultBranch=main init -q "$repo"

commit() { # message date
  git -C "$repo" add -A
  GIT_AUTHOR_DATE="$2" GIT_COMMITTER_DATE="$2" git -C "$repo" commit -q -m "$1"
}

merge() { # branch message date [--no-commit]
  GIT_AUTHOR_DATE="$3" GIT_COMMITTER_DATE="$3" git -C "$repo" merge -q --no-ff ${4:-} -m "$2" "$1" >/dev/null
}

ticket() { # branch: start a ticket branch from main
  git -C "$repo" checkout -q -b "$1" main
}

# ===================================================================== main
mkdir -p "$repo/prisma" "$repo/src/documents" "$repo/src/lib" "$repo/src/users"

cat > "$repo/package.json" <<'EOF'
{
  "name": "docs-service",
  "private": true,
  "scripts": {
    "build": "tsc -p .",
    "start": "node dist/server.js"
  },
  "dependencies": {
    "@prisma/client": "5.22.0",
    "express": "5.1.0"
  },
  "devDependencies": {
    "@types/express": "5.0.0",
    "prisma": "5.22.0",
    "typescript": "5.6.3"
  }
}
EOF

cat > "$repo/tsconfig.json" <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "outDir": "dist"
  },
  "include": ["src"]
}
EOF

cat > "$repo/README.md" <<'EOF'
# docs-service

Small document API: users sign in with a bearer session token and create, read, edit and delete
their own documents. Express 5 + Prisma (PostgreSQL).

    npm run build && npm start
EOF

cat > "$repo/prisma/schema.prisma" <<'EOF'
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        String     @id
  email     String     @unique
  name      String
  documents Document[]
  sessions  Session[]
}

model Session {
  token     String   @id
  user      User     @relation(fields: [userId], references: [id])
  userId    String
  expiresAt DateTime
}

model Document {
  id        String   @id
  owner     User     @relation(fields: [ownerId], references: [id])
  ownerId   String
  title     String
  body      String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
EOF

cat > "$repo/src/db.ts" <<'EOF'
import { PrismaClient } from '@prisma/client'

export const db = new PrismaClient()
EOF

cat > "$repo/src/session.ts" <<'EOF'
import { db } from './db'

export async function sessionUserId(header: string | undefined): Promise<string | null> {
  const token = header?.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return null
  const session = await db.session.findUnique({ where: { token } })
  return session && session.expiresAt > new Date() ? session.userId : null
}
EOF

cat > "$repo/src/auth.ts" <<'EOF'
import type { RequestHandler } from 'express'
import { db } from './db'
import { sessionUserId } from './session'

// Every route mounted after this middleware has req.user set.
export const requireUser: RequestHandler = async (req, res, next) => {
  const userId = await sessionUserId(req.get('authorization'))
  if (!userId) return res.sendStatus(401)
  const user = await db.user.findUnique({ where: { id: userId } })
  if (!user) return res.sendStatus(401)
  req.user = user
  next()
}
EOF

cat > "$repo/src/types.d.ts" <<'EOF'
import type { Document, User } from '@prisma/client'

declare global {
  namespace Express {
    interface Request {
      user: User
      doc: Document
    }
  }
}

export {}
EOF

cat > "$repo/src/errors.ts" <<'EOF'
import type { ErrorRequestHandler } from 'express'

export const errorHandler: ErrorRequestHandler = (_err, _req, res, _next) => {
  res.status(500).json({ error: 'internal error' })
}
EOF

cat > "$repo/src/app.ts" <<'EOF'
import express from 'express'
import { requireUser } from './auth'
import { documents } from './documents/routes'
import { errorHandler } from './errors'
import { users } from './users/routes'

export const app = express()

app.use(express.json())
app.get('/healthz', (_req, res) => {
  res.send('ok')
})

app.use(requireUser)
app.use('/documents', documents)
app.use('/users', users)
app.use(errorHandler)
EOF

cat > "$repo/src/server.ts" <<'EOF'
import { app } from './app'

app.listen(Number(process.env.PORT ?? 3000))
EOF

cat > "$repo/src/lib/ids.ts" <<'EOF'
import { randomUUID } from 'node:crypto'

export function newId(): string {
  return randomUUID()
}
EOF

cat > "$repo/src/users/routes.ts" <<'EOF'
import { Router } from 'express'

export const users = Router()

users.get('/me', (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name })
})
EOF

cat > "$repo/src/documents/store.ts" <<'EOF'
import type { Prisma } from '@prisma/client'
import { db } from '../db'

export function findDocument(where: Prisma.DocumentWhereUniqueInput) {
  return db.document.findUnique({ where })
}

export function saveDocument(id: string, fields: { title?: string; body?: string }) {
  return db.document.update({ where: { id }, data: fields })
}
EOF

cat > "$repo/src/documents/serialize.ts" <<'EOF'
import type { Document } from '@prisma/client'

export function toDocumentDto(doc: Document) {
  return { id: doc.id, title: doc.title, body: doc.body, updatedAt: doc.updatedAt }
}
EOF

cat > "$repo/src/documents/routes.ts" <<'EOF'
import { Router } from 'express'
import { db } from '../db'
import { newId } from '../lib/ids'
import { findDocument, saveDocument } from './store'
import { toDocumentDto } from './serialize'

export const documents = Router()

// Every /:id route below acts on a document the current user owns.
documents.param('id', async (req, res, next, id) => {
  const doc = await findDocument({ id })
  if (!doc || doc.ownerId !== req.user.id) return res.sendStatus(404)
  req.doc = doc
  next()
})

documents.get('/', async (req, res) => {
  const docs = await db.document.findMany({ where: { ownerId: req.user.id }, orderBy: { updatedAt: 'desc' } })
  res.json(docs.map(toDocumentDto))
})

documents.post('/', async (req, res) => {
  const { title, body } = req.body
  if (typeof title !== 'string' || !title.trim()) return res.sendStatus(400)
  const doc = await db.document.create({
    data: { id: newId(), ownerId: req.user.id, title, body: typeof body === 'string' ? body : '' },
  })
  res.status(201).json(toDocumentDto(doc))
})

documents.get('/:id', (req, res) => {
  res.json(toDocumentDto(req.doc))
})

documents.patch('/:id', async (req, res) => {
  const { title, body } = req.body
  if ((title !== undefined && typeof title !== 'string') || (body !== undefined && typeof body !== 'string')) {
    return res.sendStatus(400)
  }
  const doc = await saveDocument(req.doc.id, { title, body })
  res.json(toDocumentDto(doc))
})

documents.delete('/:id', async (req, res) => {
  await db.document.delete({ where: { id: req.doc.id } })
  res.sendStatus(204)
})
EOF

commit "feat: document API with per-user documents" "2026-02-02T09:00:00+0000"

# ============================================================ T1 workspaces
ticket ticket/DS-1-workspaces
mkdir -p "$repo/src/workspaces"

python3 - "$repo/prisma/schema.prisma" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('model User {', '''model Workspace {
  id        String       @id
  name      String
  ownerId   String
  members   Membership[]
  documents Document[]
  createdAt DateTime     @default(now())
}

model Membership {
  workspace   Workspace @relation(fields: [workspaceId], references: [id], onDelete: Cascade)
  workspaceId String
  user        User      @relation(fields: [userId], references: [id])
  userId      String
  role        String // "viewer" | "editor"

  @@id([workspaceId, userId])
}

model User {''', 1)
s = s.replace('  documents Document[]\n  sessions', '  documents Document[]\n  memberships Membership[]\n  sessions', 1)
s = s.replace('references: [id])\n  ownerId   String\n', '''references: [id])
  ownerId   String
  workspace   Workspace? @relation(fields: [workspaceId], references: [id])
  workspaceId String?
''', 1)
open(p, 'w').write(s)
PY

cat > "$repo/src/workspaces/access.ts" <<'EOF'
import type { Document } from '@prisma/client'
import type { RequestHandler } from 'express'
import { db } from '../db'
import { findDocument } from '../documents/store'

export type Access = 'read' | 'write' | 'own'

export async function workspaceRole(userId: string, workspaceId: string): Promise<string | null> {
  const membership = await db.membership.findUnique({ where: { workspaceId_userId: { workspaceId, userId } } })
  return membership?.role ?? null
}

// The owner can do anything; workspace editors can read and write; workspace viewers can read.
export async function hasAccess(userId: string, doc: Document, access: Access): Promise<boolean> {
  if (doc.ownerId === userId) return true
  if (access === 'own' || !doc.workspaceId) return false
  const role = await workspaceRole(userId, doc.workspaceId)
  if (!role) return false
  return access === 'read' || role === 'editor'
}

// Loads the :id document into req.doc if the current user has `access` to it, else 404.
export function loadDocument(access: Access): RequestHandler {
  return async (req, res, next) => {
    const doc = await findDocument({ id: req.params.id })
    if (!doc || !(await hasAccess(req.user.id, doc, access))) return res.sendStatus(404)
    req.doc = doc
    next()
  }
}
EOF

cat > "$repo/src/workspaces/routes.ts" <<'EOF'
import { Router } from 'express'
import { db } from '../db'
import { newId } from '../lib/ids'

export const workspaces = Router()

workspaces.post('/', async (req, res) => {
  const { name } = req.body
  if (typeof name !== 'string' || !name.trim()) return res.sendStatus(400)
  const workspace = await db.workspace.create({
    data: { id: newId(), name, ownerId: req.user.id, members: { create: { userId: req.user.id, role: 'editor' } } },
  })
  res.status(201).json({ id: workspace.id, name: workspace.name })
})

// Only the workspace owner manages members.
async function ownedWorkspace(workspaceId: string, userId: string) {
  const workspace = await db.workspace.findUnique({ where: { id: workspaceId } })
  return workspace && workspace.ownerId === userId ? workspace : null
}

workspaces.put('/:workspaceId/members/:userId', async (req, res) => {
  const { role } = req.body
  if (role !== 'viewer' && role !== 'editor') return res.sendStatus(400)
  const workspace = await ownedWorkspace(req.params.workspaceId, req.user.id)
  if (!workspace) return res.sendStatus(404)
  if (req.params.userId === workspace.ownerId) return res.sendStatus(400)
  const user = await db.user.findUnique({ where: { id: req.params.userId } })
  if (!user) return res.sendStatus(404)
  await db.membership.upsert({
    where: { workspaceId_userId: { workspaceId: workspace.id, userId: user.id } },
    create: { workspaceId: workspace.id, userId: user.id, role },
    update: { role },
  })
  res.sendStatus(204)
})

workspaces.delete('/:workspaceId/members/:userId', async (req, res) => {
  const workspace = await ownedWorkspace(req.params.workspaceId, req.user.id)
  if (!workspace) return res.sendStatus(404)
  if (req.params.userId === workspace.ownerId) return res.sendStatus(400)
  // A removed member keeps their own documents, but they leave the workspace with them.
  await db.$transaction([
    db.membership.deleteMany({ where: { workspaceId: workspace.id, userId: req.params.userId } }),
    db.document.updateMany({ where: { workspaceId: workspace.id, ownerId: req.params.userId }, data: { workspaceId: null } }),
  ])
  res.sendStatus(204)
})
EOF

python3 - "$repo/src/documents/store.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('''  return db.document.findUnique({ where })
''', '''  return db.document.findUnique({
    where,
    include: { workspace: { include: { members: { include: { user: true } } } } },
  })
''', 1)
open(p, 'w').write(s)
PY

cat > "$repo/src/documents/serialize.ts" <<'EOF'
import type { Document, Membership, User } from '@prisma/client'

type Sharing = { workspace?: { members: (Membership & { user: User })[] } | null }

// sharedWith is included when the document was loaded with its workspace members (findDocument).
export function toDocumentDto(doc: Document & Sharing) {
  return {
    id: doc.id,
    title: doc.title,
    body: doc.body,
    updatedAt: doc.updatedAt,
    workspaceId: doc.workspaceId,
    ...(doc.workspace !== undefined && {
      sharedWith: (doc.workspace?.members ?? []).map((m) => ({ name: m.user.name, email: m.user.email, role: m.role })),
    }),
  }
}
EOF

python3 - "$repo/src/documents/routes.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
def sub(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new, 1)
sub("import { newId } from '../lib/ids'\n", "import { newId } from '../lib/ids'\nimport { loadDocument, workspaceRole } from '../workspaces/access'\n")
sub('''// Every /:id route below acts on a document the current user owns.
documents.param('id', async (req, res, next, id) => {
  const doc = await findDocument({ id })
  if (!doc || doc.ownerId !== req.user.id) return res.sendStatus(404)
  req.doc = doc
  next()
})

''', '')
sub("import { findDocument, saveDocument } from './store'", "import { saveDocument } from './store'")
sub('''  const docs = await db.document.findMany({ where: { ownerId: req.user.id }, orderBy: { updatedAt: 'desc' } })
''', '''  const memberships = await db.membership.findMany({ where: { userId: req.user.id } })
  const docs = await db.document.findMany({
    where: { OR: [{ ownerId: req.user.id }, { workspaceId: { in: memberships.map((m) => m.workspaceId) } }] },
    orderBy: { updatedAt: 'desc' },
  })
''')
sub('''  const { title, body } = req.body
  if (typeof title !== 'string' || !title.trim()) return res.sendStatus(400)
  const doc = await db.document.create({
    data: { id: newId(), ownerId: req.user.id, title, body: typeof body === 'string' ? body : '' },
''', '''  const { title, body, workspaceId } = req.body
  if (typeof title !== 'string' || !title.trim()) return res.sendStatus(400)
  if (workspaceId !== undefined) {
    if (typeof workspaceId !== 'string') return res.sendStatus(400)
    if ((await workspaceRole(req.user.id, workspaceId)) !== 'editor') return res.sendStatus(403)
  }
  const doc = await db.document.create({
    data: { id: newId(), ownerId: req.user.id, workspaceId, title, body: typeof body === 'string' ? body : '' },
''')
sub("documents.get('/:id', (req, res) => {", "documents.get('/:id', loadDocument('read'), (req, res) => {")
sub("documents.patch('/:id', async (req, res) => {", "documents.patch('/:id', loadDocument('write'), async (req, res) => {")
sub("documents.delete('/:id', async (req, res) => {", "documents.delete('/:id', loadDocument('own'), async (req, res) => {")
open(p, 'w').write(s)
PY

python3 - "$repo/src/app.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("import { users } from './users/routes'\n", "import { users } from './users/routes'\nimport { workspaces } from './workspaces/routes'\n", 1)
s = s.replace("app.use('/users', users)\n", "app.use('/users', users)\napp.use('/workspaces', workspaces)\n", 1)
open(p, 'w').write(s)
PY

commit "feat(workspaces): share documents with workspace members (DS-1)" "2026-02-03T09:00:00+0000"

# ============================================================== T2 versions
t2() { # variant: buggy | clean
  python3 - "$repo/prisma/schema.prisma" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('  updatedAt DateTime @updatedAt\n}\n', '''  updatedAt DateTime @updatedAt
  versions  DocumentVersion[]
}

model DocumentVersion {
  id         String   @id
  document   Document @relation(fields: [documentId], references: [id], onDelete: Cascade)
  documentId String
  content    Json
  createdAt  DateTime @default(now())

  @@index([documentId, id])
}
''', 1)
open(p, 'w').write(s)
PY

  cat > "$repo/src/lib/ids.ts" <<'EOF'
// Each running instance needs its own WORKER_ID, or two instances can mint the same id.
const WORKER = process.env.WORKER_ID ?? ''
if (!/^\d{3}$/.test(WORKER)) throw new Error('WORKER_ID must be a 3-digit id, unique per instance')

let lastMs = 0
let seq = 0

// Ids sort by creation time (version history is listed by id): milliseconds, worker, sequence.
export function newId(): string {
  const now = Math.max(Date.now(), lastMs)
  seq = now === lastMs ? seq + 1 : 0
  lastMs = now
  return `${now.toString(36).padStart(9, '0')}${WORKER}${seq.toString(36).padStart(4, '0')}`
}
EOF

  {
    cat <<'EOF'
import type { Document, Prisma } from '@prisma/client'
import { db } from '../db'
import { newId } from '../lib/ids'

EOF
    if [ "$1" = buggy ]; then
      cat <<'EOF'
// The editable part of a document: everything but identity and bookkeeping.
function contentOf(doc: Document): Prisma.InputJsonObject {
  const { id, ownerId, createdAt, updatedAt, ...content } = doc
  return content
}
EOF
    else
      cat <<'EOF'
// The editable part of a document.
function contentOf(doc: Document): Prisma.InputJsonObject {
  return { title: doc.title, body: doc.body }
}
EOF
    fi
    cat <<'EOF'

// Snapshot the document as it is now, before the caller overwrites it in the same transaction.
// The row stays locked until that transaction ends, so concurrent saves are snapshotted in turn.
export async function recordVersion(tx: Prisma.TransactionClient, documentId: string) {
  await tx.$queryRaw`SELECT id FROM "Document" WHERE id = ${documentId} FOR UPDATE`
  const doc = await tx.document.findUniqueOrThrow({ where: { id: documentId } })
  await tx.documentVersion.create({ data: { id: newId(), documentId, content: contentOf(doc) } })
}

export function listVersions(documentId: string) {
  return db.documentVersion.findMany({
    where: { documentId },
    select: { id: true, createdAt: true },
    orderBy: { id: 'desc' },
  })
}

export function getVersion(documentId: string, versionId: string) {
  return db.documentVersion.findFirst({ where: { id: versionId, documentId } })
}

// Restoring is itself an edit: the current content is snapshotted first, so a restore can be undone.
export function restoreVersion(documentId: string, versionId: string) {
  return db.$transaction(async (tx) => {
    const version = await tx.documentVersion.findFirst({ where: { id: versionId, documentId } })
    if (!version) return null
    await recordVersion(tx, documentId)
EOF
    if [ "$1" = buggy ]; then
      cat <<'EOF'
    return tx.document.update({ where: { id: documentId }, data: version.content as Prisma.DocumentUpdateInput })
  })
}
EOF
    else
      cat <<'EOF'
    const { title, body } = version.content as { title: string; body: string }
    return tx.document.update({ where: { id: documentId }, data: { title, body } })
  })
}
EOF
    fi
  } > "$repo/src/documents/versions.ts"

  python3 - "$repo/src/documents/store.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("import { db } from '../db'\n", "import { db } from '../db'\nimport { recordVersion } from './versions'\n", 1)
old = '''export function saveDocument(id: string, fields: { title?: string; body?: string }) {
  return db.document.update({ where: { id }, data: fields })
}
'''
assert old in s
s = s.replace(old, '''export function saveDocument(id: string, fields: { title?: string; body?: string }) {
  return db.$transaction(async (tx) => {
    await recordVersion(tx, id)
    return tx.document.update({ where: { id }, data: fields })
  })
}
''', 1)
open(p, 'w').write(s)
PY

  python3 - "$repo/src/documents/routes.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("import { toDocumentDto } from './serialize'\n",
              "import { toDocumentDto } from './serialize'\nimport { getVersion, listVersions, restoreVersion } from './versions'\n", 1)
s += '''
documents.get('/:id/versions', async (req, res) => {
  res.json(await listVersions(req.params.id))
})

documents.get('/:id/versions/:versionId', async (req, res) => {
  const version = await getVersion(req.params.id, req.params.versionId)
  if (!version) return res.sendStatus(404)
  res.json(version)
})

documents.post('/:id/versions/:versionId/restore', async (req, res) => {
  const doc = await restoreVersion(req.params.id, req.params.versionId)
  if (!doc) return res.sendStatus(404)
  res.json(toDocumentDto(doc))
})
'''
open(p, 'w').write(s)
PY
}

ticket ticket/DS-2-versions
t2 buggy
commit "feat(documents): version history with restore (DS-2)" "2026-02-04T09:00:00+0000"
ticket ticket/DS-2-versions-clean
t2 clean
commit "feat(documents): version history with restore (DS-2)" "2026-02-04T09:00:00+0000"

# =========================================================== T3 share links
t3() { # variant: buggy | clean
  mkdir -p "$repo/src/sharing"
  python3 - "$repo/prisma/schema.prisma" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('  body      String\n', '  body      String\n  shareToken String?  @unique\n', 1)
open(p, 'w').write(s)
PY

  {
    if [ "$1" = clean ]; then
      cat <<'EOF'
import { randomBytes } from 'node:crypto'
import { Router } from 'express'
import { db } from '../db'
import { findDocument } from '../documents/store'
EOF
    else
      cat <<'EOF'
import { Router } from 'express'
import { db } from '../db'
import { toDocumentDto } from '../documents/serialize'
import { findDocument } from '../documents/store'
import { newId } from '../lib/ids'
EOF
    fi
    cat <<'EOF'

// Signed-in owner: create or revoke a document's share link.
export const sharing = Router()

async function ownedDocument(id: string, userId: string) {
  const doc = await findDocument({ id })
  return doc && doc.ownerId === userId ? doc : null
}

sharing.put('/:id/share', async (req, res) => {
  const doc = await ownedDocument(req.params.id, req.user.id)
  if (!doc) return res.sendStatus(404)
EOF
    echo "  // Set a token only if there is none, so repeated or concurrent requests return the same link."
    if [ "$1" = clean ]; then
      echo "  const token = randomBytes(32).toString('base64url')"
    else
      echo "  const token = newId()"
    fi
    cat <<'EOF'
  await db.document.updateMany({ where: { id: doc.id, shareToken: null }, data: { shareToken: token } })
  const { shareToken } = await db.document.findUniqueOrThrow({ where: { id: doc.id }, select: { shareToken: true } })
  if (!shareToken) return res.sendStatus(409)
  res.json({ url: `/s/${shareToken}` })
})

sharing.delete('/:id/share', async (req, res) => {
  const doc = await ownedDocument(req.params.id, req.user.id)
  if (!doc) return res.sendStatus(404)
  await db.document.update({ where: { id: doc.id }, data: { shareToken: null } })
  res.sendStatus(204)
})

// Anyone with the link: a read-only view, no sign-in.
export const publicShares = Router()

publicShares.get('/:token', async (req, res) => {
  const doc = await findDocument({ shareToken: req.params.token })
  if (!doc) return res.sendStatus(404)
  res.set('Cache-Control', 'no-store')
EOF
    if [ "$1" = clean ]; then
      echo "  res.json({ title: doc.title, body: doc.body, updatedAt: doc.updatedAt })"
    else
      echo "  res.json(toDocumentDto(doc))"
    fi
    echo "})"
  } > "$repo/src/sharing/routes.ts"

  python3 - "$repo/src/app.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
def sub(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new, 1)
sub("import { errorHandler } from './errors'\n", "import { errorHandler } from './errors'\nimport { publicShares, sharing } from './sharing/routes'\n")
sub("  res.send('ok')\n})\n", "  res.send('ok')\n})\napp.use('/s', publicShares)\n")
sub("app.use('/documents', documents)\n", "app.use('/documents', documents)\napp.use('/documents', sharing)\n")
open(p, 'w').write(s)
PY
}

ticket ticket/DS-3-share-links
t3 buggy
commit "feat(sharing): public read-only share links (DS-3)" "2026-02-05T09:00:00+0000"
ticket ticket/DS-3-share-links-clean
t3 clean
commit "feat(sharing): public read-only share links (DS-3)" "2026-02-05T09:00:00+0000"

# ==================================================================== epics
git -C "$repo" checkout -q -b epic/doc-sharing main
merge ticket/DS-1-workspaces "Merge DS-1 workspaces into epic/doc-sharing" "2026-02-06T09:00:00+0000"
merge ticket/DS-2-versions "Merge DS-2 version history into epic/doc-sharing" "2026-02-07T09:00:00+0000"
merge ticket/DS-3-share-links "Merge DS-3 share links into epic/doc-sharing" "2026-02-08T09:00:00+0000"

git -C "$repo" checkout -q -b epic/doc-sharing-clean main
merge ticket/DS-1-workspaces "Merge DS-1 workspaces into epic/doc-sharing-clean" "2026-02-06T09:00:00+0000"
merge ticket/DS-2-versions-clean "Merge DS-2 version history into epic/doc-sharing-clean" "2026-02-07T09:00:00+0000" --no-commit
python3 - "$repo/src/documents/routes.ts" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
for old, new in [
    ("documents.get('/:id/versions', async", "documents.get('/:id/versions', loadDocument('read'), async"),
    ("documents.get('/:id/versions/:versionId', async", "documents.get('/:id/versions/:versionId', loadDocument('read'), async"),
    ("documents.post('/:id/versions/:versionId/restore', async", "documents.post('/:id/versions/:versionId/restore', loadDocument('write'), async"),
]:
    assert old in s, old
    s = s.replace(old, new, 1)
open(p, 'w').write(s)
PY
git -C "$repo" add -A
GIT_AUTHOR_DATE="2026-02-07T09:00:00+0000" GIT_COMMITTER_DATE="2026-02-07T09:00:00+0000" \
  git -C "$repo" commit -q --no-edit
merge ticket/DS-3-share-links-clean "Merge DS-3 share links into epic/doc-sharing-clean" "2026-02-08T09:00:00+0000"

git -C "$repo" checkout -q main
for ref in main ticket/DS-1-workspaces ticket/DS-2-versions ticket/DS-3-share-links epic/doc-sharing \
           ticket/DS-2-versions-clean ticket/DS-3-share-links-clean epic/doc-sharing-clean; do
  printf '%s %s\n' "$ref" "$(git -C "$repo" rev-parse "$ref")"
done
