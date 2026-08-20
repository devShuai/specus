import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const repositoryRoot = path.resolve(scriptDir, '..', '..', '..')
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(repositoryRoot, relativePath), 'utf8'))

const peerSchema = readJson('protocol/schemas/peer-control.schema.json')
const authSchema = readJson('protocol/schemas/client-auth-login.schema.json')
const vectors = readJson('protocol/test-vectors/peer-service-discovery-v2.json')
const ajv = new Ajv2020({ allErrors: true, strict: false })
addFormats(ajv)
const validatePeer = ajv.compile(peerSchema)
const validateAuth = ajv.compile(authSchema)
const expectedRuntimes = ['java', 'go', 'dotnet', 'android']
const forbiddenReportFields = [
  'sourceClientId', 'sourceClientName', 'sourceVirtualIp', 'sourcePublicKey', 'sourceKeyEpoch',
  'targetClientId', 'targetClientName', 'targetVirtualIp', 'targetPublicKey',
  'sessionId', 'token', 'publisherClientId', 'publisherClientName', 'publisherSessionId',
]

const failures = []
for (const runtime of expectedRuntimes) {
  const report = vectors.serviceReports?.[runtime]
  if (!report || !validatePeer(report)) {
    failures.push(`${runtime} service-report: ${ajv.errorsText(validatePeer.errors)}`)
  }
  for (const field of forbiddenReportFields) {
    if (Object.hasOwn(report ?? {}, field)) failures.push(`${runtime} service-report contains server-bound ${field}`)
  }
  const auth = vectors.clientAuthRequests?.[runtime]
  if (!auth || !validateAuth(auth)) {
    failures.push(`${runtime} client-auth: ${ajv.errorsText(validateAuth.errors)}`)
  }
  const capabilities = auth?.environment?.clientPeerServiceCapabilities
  if (capabilities?.version !== vectors.protocolVersion
      || JSON.stringify(capabilities?.applications) !== JSON.stringify(vectors.applications)) {
    failures.push(`${runtime} capability enum/version differs from the shared vector`)
  }
}

if (failures.length) {
  process.stderr.write(`${failures.join('\n')}\n`)
  process.exit(1)
}
process.stdout.write(`validated ${expectedRuntimes.length} service reports and client-auth fixtures\n`)
