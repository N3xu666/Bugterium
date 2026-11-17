#!/usr/bin/env node
/**
 * Fail-closed npm dependency audit gate with explicit, auto-expiring VEX exceptions.
 * Reads `npm audit --omit=dev --audit-level=high --json` from stdin so no filesystem
 * paths or child_process executions are needed.
 */

import process from 'node:process';
import { Buffer } from 'node:buffer';

const ALLOWED_BELOW_THRESHOLD = new Set(['info', 'low', 'moderate']);

const VEX_EXCEPTIONS = new Map([
  [
    'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
    {
      cve: 'CVE-2026-112366',
      packageName: 'picomatch',
      rationale:
        'Build-time glob ReDoS inside Docusaurus/Webpack bundler only; never exposed to untrusted runtime input or shipped to Cloudflare Pages static output; latest upstream npm release (4.0.7) has no patched version.',
      reviewAfter: '2026-12-17',
    },
  ],
]);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function fail(message) {
  console.error(`[AUDIT FAIL] ${message}`);
  process.exit(1);
}

function hasNonBreakingFix(fixAvailable) {
  if (fixAvailable === true) return true;
  if (fixAvailable && typeof fixAvailable === 'object') {
    return fixAvailable.isSemVerMajor === false;
  }
  return false;
}

function validateAdvisoryObject(pkgName, viaObj, fixAvailable, matchedVexUrls, errors) {
  if (typeof viaObj.severity === 'string' && ALLOWED_BELOW_THRESHOLD.has(viaObj.severity)) {
    return true;
  }

  const url = typeof viaObj.url === 'string' ? viaObj.url : '';
  const vex = url ? VEX_EXCEPTIONS.get(url) : undefined;
  if (!vex) {
    const title = typeof viaObj.title === 'string' ? viaObj.title : 'no-title';
    const sev = typeof viaObj.severity === 'string' ? viaObj.severity : 'unknown';
    errors.push(`Unexempted ${sev} advisory on '${pkgName}': ${url || 'missing-url'} (${title})`);
    return false;
  }

  if (pkgName !== vex.packageName || viaObj.name !== vex.packageName) {
    errors.push(
      `VEX advisory ${url} target mismatch: expected '${vex.packageName}', got pkg='${pkgName}', advisoryName='${String(viaObj.name)}'`,
    );
    return false;
  }

  if (hasNonBreakingFix(fixAvailable)) {
    errors.push(
      `VEX auto-expired for ${url} (${vex.cve}) on '${pkgName}': a non-breaking fix is now available. Update dependencies and remove this VEX exception.`,
    );
    return false;
  }

  matchedVexUrls.add(url);
  return true;
}

/**
 * Check via fixed-point propagation that every blocked vulnerability node
 * reaches at least one valid root advisory object or below-threshold package,
 * preventing disconnected cycles with zero leaves.
 */
function findUnresolvedCycles(vulnMap) {
  const resolvedNodes = new Set();
  for (const [pkgName, entry] of vulnMap.entries()) {
    if (!entry || typeof entry !== 'object') continue;
    if (ALLOWED_BELOW_THRESHOLD.has(entry.severity)) {
      resolvedNodes.add(pkgName);
      continue;
    }
    if (Array.isArray(entry.via) && entry.via.some((v) => v && typeof v === 'object')) {
      resolvedNodes.add(pkgName);
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [pkgName, entry] of vulnMap.entries()) {
      if (resolvedNodes.has(pkgName) || !entry || !Array.isArray(entry.via)) continue;
      if (entry.via.some((v) => typeof v === 'string' && resolvedNodes.has(v))) {
        resolvedNodes.add(pkgName);
        changed = true;
      }
    }
  }

  const cycleErrors = [];
  for (const [pkgName, entry] of vulnMap.entries()) {
    if (entry && typeof entry === 'object' && !ALLOWED_BELOW_THRESHOLD.has(entry.severity) && !resolvedNodes.has(pkgName)) {
      cycleErrors.push(`Entry '${pkgName}' has no valid root advisory leaf (unresolved or pure cycle).`);
    }
  }
  return cycleErrors;
}

async function main() {
  const raw = (await readStdin()).replace(/^\uFEFF/, '');
  if (!raw.trim()) {
    fail('Received empty input instead of npm audit JSON.');
  }

  let report;
  try {
    report = JSON.parse(raw);
  } catch (err) {
    fail(`Failed to parse npm audit JSON: ${err.message}`);
  }

  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    fail('Malformed npm audit JSON root value.');
  }

  if (report.error) {
    fail(`npm audit returned an error payload: ${JSON.stringify(report.error)}`);
  }

  if (!report.vulnerabilities || typeof report.vulnerabilities !== 'object' || Array.isArray(report.vulnerabilities)) {
    fail("Missing 'vulnerabilities' object in npm audit JSON.");
  }

  if (!report.metadata?.vulnerabilities || typeof report.metadata.vulnerabilities !== 'object') {
    fail("Missing 'metadata.vulnerabilities' summary in npm audit JSON.");
  }

  const vulnMap = new Map(Object.entries(report.vulnerabilities));
  const highCount = Number(report.metadata.vulnerabilities.high || 0);
  const criticalCount = Number(report.metadata.vulnerabilities.critical || 0);
  const totalBlocked = highCount + criticalCount;
  const auditExit = process.env.AUDIT_EXIT;

  if (auditExit !== undefined && auditExit !== '0' && totalBlocked === 0 && vulnMap.size === 0) {
    fail(`npm audit exited with code ${auditExit} while reporting 0 vulnerabilities (fail-closed).`);
  }

  const errors = [];
  const matchedVexUrls = new Set();

  for (const [pkgName, entry] of vulnMap.entries()) {
    if (!entry || typeof entry !== 'object') {
      errors.push(`Malformed vulnerability entry for '${pkgName}'.`);
      continue;
    }

    const isBlockedSeverity = !ALLOWED_BELOW_THRESHOLD.has(entry.severity);
    if (!Array.isArray(entry.via) || (isBlockedSeverity && entry.via.length === 0)) {
      errors.push(`Blocked ${String(entry.severity)} entry '${pkgName}' has no 'via' array.`);
      continue;
    }

    for (const viaItem of entry.via) {
      if (viaItem && typeof viaItem === 'object') {
        validateAdvisoryObject(pkgName, viaItem, entry.fixAvailable, matchedVexUrls, errors);
      } else if (typeof viaItem === 'string') {
        if (!vulnMap.has(viaItem)) {
          errors.push(`Entry '${pkgName}' references unknown dependency '${viaItem}'.`);
        }
      } else {
        errors.push(`Malformed 'via' element on '${pkgName}'.`);
      }
    }
  }

  errors.push(...findUnresolvedCycles(vulnMap));

  if (totalBlocked > 0 && matchedVexUrls.size === 0) {
    errors.push(
      `Metadata reports ${totalBlocked} high/critical vulnerability(ies), but none resolved to an exempted VEX advisory.`,
    );
  }

  if (errors.length > 0) {
    console.error(`[AUDIT FAIL] Found ${errors.length} unexempted/invalid finding(s):`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  if (totalBlocked === 0) {
    console.log('[AUDIT PASS] 0 high/critical runtime vulnerabilities found.');
    return;
  }

  const today = new Date().toISOString().slice(0, 10);
  for (const url of matchedVexUrls) {
    const vex = VEX_EXCEPTIONS.get(url);
    if (today >= vex.reviewAfter) {
      console.warn(
        `::warning::VEX exception ${url} (${vex.cve}) passed review date ${vex.reviewAfter}; check npm for a patched ${vex.packageName} release.`,
      );
    }
    console.log(`[VEX PASS] Exempted ${vex.cve} (${url}) on '${vex.packageName}': ${vex.rationale}`);
  }
  console.log(
    `[AUDIT PASS] ${totalBlocked} reported high/critical chain node(s) resolved strictly to exempted VEX advisory (${matchedVexUrls.size} active).`,
  );
}

main().catch((err) => {
  fail(`Unexpected exception: ${err instanceof Error ? err.message : String(err)}`);
});
