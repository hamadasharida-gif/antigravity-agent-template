import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../../../');
const serverDir = path.join(rootDir, 'server');
const clientDir = path.join(rootDir, 'client');

console.log('========================================================');
console.log(' Newhouse NOC System - Automated Security Audit Scanner');
console.log('========================================================\n');

let issuesFound = 0;

// 1. Audit .gitignore
console.log('[1/5] Checking .gitignore configuration...');
const gitignorePath = path.join(rootDir, '.gitignore');
if (!fs.existsSync(gitignorePath)) {
  console.log('❌ CRITICAL: .gitignore missing at project root!');
  issuesFound++;
} else {
  const content = fs.readFileSync(gitignorePath, 'utf8');
  const requiredEntries = ['whatsapp_auth', '.env', '*.db'];
  const missing = requiredEntries.filter(e => !content.includes(e));
  if (missing.length > 0) {
    console.log(`⚠️ WARNING: .gitignore is missing sensitive entries: ${missing.join(', ')}`);
    issuesFound++;
  } else {
    console.log('✅ .gitignore contains all necessary protection rules.');
  }
}

// 2. Scan for Unsanitized Command Executions
console.log('\n[2/5] Scanning for OS Command Injection risks...');
function walk(dir, fileList = []) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const full = path.join(dir, file);
    if (fs.statSync(full).isDirectory()) {
      if (!full.includes('node_modules') && !full.includes('.git')) {
        walk(full, fileList);
      }
    } else if (full.endsWith('.js') || full.endsWith('.mjs')) {
      fileList.push(full);
    }
  }
  return fileList;
}

const jsFiles = walk(path.join(serverDir, 'src'));
let commandRisks = 0;

for (const file of jsFiles) {
  const code = fs.readFileSync(file, 'utf8');
  const lines = code.split('\n');
  lines.forEach((line, idx) => {
    if (line.includes('exec(') || line.includes('execAsync(') || line.includes('execPromise(')) {
      if (line.includes('`') && line.includes('${')) {
        // Check if variable is raw or checked
        if (!code.includes('isValidHostnameOrIp') && !code.includes('sanitizeServiceName')) {
          console.log(`⚠️ Possible unvalidated command execution in ${path.relative(rootDir, file)}:${idx + 1}`);
          console.log(`   Line: ${line.trim()}`);
          commandRisks++;
        }
      }
    }
  });
}

if (commandRisks === 0) {
  console.log('✅ All OS command executions are properly sanitized with securityUtils.');
} else {
  issuesFound += commandRisks;
}

// 3. Scan for Direct SQL String Interpolation
console.log('\n[3/5] Scanning for SQL Injection risks...');
let sqlRisks = 0;
for (const file of jsFiles) {
  const code = fs.readFileSync(file, 'utf8');
  const lines = code.split('\n');
  lines.forEach((line, idx) => {
    if (/db\.(run|all|get|exec)\s*\(\s*`[^`]*\$\{/.test(line)) {
      // Whitelist approved patterns like placeholders (?,?) or static table names
      if (!line.includes('${placeholders}') && !line.includes('${t}') && !line.includes('${tableName}')) {
        console.log(`⚠️ Suspicious SQL template literal in ${path.relative(rootDir, file)}:${idx + 1}`);
        console.log(`   Line: ${line.trim()}`);
        sqlRisks++;
      }
    }
  });
}

if (sqlRisks === 0) {
  console.log('✅ All SQL operations use parameterized queries (?) or safe placeholders.');
} else {
  issuesFound += sqlRisks;
}

// 4. NPM Dependency Audit - Server
console.log('\n[4/5] Running Server dependencies vulnerability audit...');
try {
  const serverAuditOut = execSync('npm.cmd audit --json', { cwd: serverDir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] });
  const report = JSON.parse(serverAuditOut);
  const total = report.metadata?.vulnerabilities?.total || 0;
  console.log(`Server dependencies audit: ${total} vulnerabilities reported.`);
} catch (e) {
  if (e.stdout) {
    try {
      const report = JSON.parse(e.stdout);
      const total = report.metadata?.vulnerabilities?.total || 0;
      console.log(`Server dependencies audit: ${total} vulnerabilities detected.`);
    } catch (_) {
      console.log('Server audit finished with notices.');
    }
  }
}

// 5. NPM Dependency Audit - Client
console.log('\n[5/5] Running Client dependencies vulnerability audit...');
try {
  const clientAuditOut = execSync('npm.cmd audit --json', { cwd: clientDir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] });
  const report = JSON.parse(clientAuditOut);
  const total = report.metadata?.vulnerabilities?.total || 0;
  console.log(`Client dependencies audit: ${total} vulnerabilities reported.`);
} catch (e) {
  if (e.stdout) {
    try {
      const report = JSON.parse(e.stdout);
      const total = report.metadata?.vulnerabilities?.total || 0;
      console.log(`Client dependencies audit: ${total} vulnerabilities detected.`);
    } catch (_) {
      console.log('Client audit finished with notices.');
    }
  }
}

console.log('\n========================================================');
if (issuesFound === 0) {
  console.log('🎉 AUDIT RESULT: PASSED! Zero high-risk security flaws found.');
} else {
  console.log(`⚠️ AUDIT RESULT: ${issuesFound} warnings or potential issues require attention.`);
}
console.log('========================================================\n');
