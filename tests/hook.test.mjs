import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = fs.mkdtempSync(path.join(os.tmpdir(), "agentignore-test-"));
const HOOK = path.join(FIXTURE, ".claude", "hooks", "agentignore.mjs");
const STRIPE = "sk_live_abcdefghijklmnopqrstuvwx";
const REDACTED = "[blocked by .agentignore]";

let rulePass = 0;
let ruleFail = 0;
let limitsConfirmed = 0;
let limitsClosed = 0;

try {
  setup();

  const ruleCases = [
    // 1. Load .agentignore and parse path rules.
    ["file rule: Read is denied", () => {
      assert.equal(verdict(pre("Read", { file_path: "secrets/api-key.txt" })), "deny");
    }],
    ["directory rule: a nested Read is denied", () => {
      assert.equal(verdict(pre("Read", { file_path: "private/notes.txt" })), "deny");
    }],
    ["unanchored rule: a basename at depth is denied", () => {
      assert.equal(verdict(pre("Read", { file_path: "config/.env" })), "deny");
    }],

    // 2. Extract path-shaped strings from the tool input.
    ["Write into a blocked directory is denied", () => {
      assert.equal(verdict(pre("Write", { file_path: "private/new.txt" })), "deny");
    }],
    ["absolute native path is denied", () => {
      assert.equal(verdict(pre("Edit", { file_path: path.join(FIXTURE, "private", "notes.txt") })), "deny");
    }],
    ["Grep scope is denied", () => {
      assert.equal(verdict(pre("Grep", { pattern: "token", path: "private" })), "deny");
    }],
    ["Glob pattern is denied", () => {
      assert.equal(verdict(pre("Glob", { pattern: "private/**" })), "deny");
    }],
    ["unknown tool input is scanned", () => {
      assert.equal(verdict(pre("mcp__files__read", { target: "secrets/api-key.txt" })), "deny");
    }],
    ["unknown tool bare dotfile is scanned", () => {
      assert.equal(verdict(pre("mcp__files__read", { target: ".env" })), "deny");
    }],
    ["unknown tool scans past a benign path key", () => {
      assert.equal(
        verdict(pre("mcp__files__read", { path: "notes.txt", target: "secrets/api-key.txt" })),
        "deny",
      );
    }],
    ["clean path is allowed", () => {
      assert.equal(verdict(pre("Read", { file_path: "notes.txt" })), "allow");
    }],
    ["path outside the repo is allowed", () => {
      assert.equal(verdict(pre("Read", { file_path: path.join(os.tmpdir(), "outside-agentignore.txt") })), "allow");
    }],

    // 3. Bash is not parsed: literal protected path or allow.
    ["Bash literal file path is denied", () => {
      assert.equal(verdict(pre("Bash", { command: "cat secrets/api-key.txt" })), "deny");
    }],
    ["Bash literal dotenv is denied", () => {
      assert.equal(verdict(pre("Bash", { command: "cat config/.env" })), "deny");
    }],
    ["Bash unrelated command is allowed", () => {
      assert.equal(verdict(pre("Bash", { command: "node --version" })), "allow");
    }],
    ["Bash similar filename is allowed", () => {
      assert.equal(verdict(pre("Bash", { command: "cat secrets/api-key.txt.bak" })), "allow");
    }],

    // 4. The policy surface is always denied.
    ["Read of .agentignore is denied", () => {
      assert.equal(verdict(pre("Read", { file_path: ".agentignore" })), "deny");
    }],
    ["absolute path to .agentignore is denied", () => {
      assert.equal(verdict(pre("Read", { file_path: path.join(FIXTURE, ".agentignore") })), "deny");
    }],
    ["Bash read of .agentignore is denied", () => {
      assert.equal(verdict(pre("Bash", { command: "cat .agentignore" })), "deny");
    }],
    ["unknown tool policy surface is scanned", () => {
      assert.equal(verdict(pre("mcp__files__read", { target: ".agentignore" })), "deny");
    }],
    ["Write to the hook is denied", () => {
      assert.equal(verdict(pre("Write", { file_path: ".claude/hooks/agentignore.mjs" })), "deny");
    }],
    ["Read of harness settings is denied", () => {
      assert.equal(verdict(pre("Read", { file_path: ".claude/settings.json" })), "deny");
    }],
    ["Write to local harness settings is denied", () => {
      assert.equal(verdict(pre("Write", { file_path: ".claude/settings.local.json" })), "deny");
    }],
    ["Bash write to harness settings is denied", () => {
      assert.equal(verdict(pre("Bash", { command: "echo {} > .claude/settings.json" })), "deny");
    }],

    // 5. PostToolUse scrub patterns.
    ["scrub: Stripe-shaped result is replaced", () => {
      const decision = post(`prefix ${STRIPE} suffix`);
      assert.equal(verdict(decision), "block");
      assert.equal(decision.hookSpecificOutput.updatedToolOutput, REDACTED);
      assert.ok(!JSON.stringify(decision).includes(STRIPE), "replacement must not echo the secret");
    }],
    ["scrub: every shipped pattern blocks", () => {
      // Fake fixtures for the scrub patterns, not real credentials.
      const samples = [
        STRIPE,
        `ghp_${"a".repeat(36)}`,
        "AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwx",
      ];
      for (const sample of samples) {
        assert.equal(verdict(post(sample)), "block", sample.slice(0, 16));
      }
    }],
    ["scrub: private key is blocked case-insensitively", () => {
      assert.equal(verdict(post("-----begin rsa private key-----")), "block");
    }],
    ["scrub: object result is replaced with its shape intact", () => {
      const decision = post({ stdout: STRIPE, stderr: "", interrupted: false, isImage: false });
      assert.equal(verdict(decision), "block");
      assert.deepEqual(decision.hookSpecificOutput.updatedToolOutput, {
        stdout: REDACTED,
        stderr: REDACTED,
        interrupted: false,
        isImage: false,
      });
      assert.ok(!JSON.stringify(decision).includes(STRIPE), "replacement must not echo the secret");
    }],
    ["scrub: array result is replaced with its shape intact", () => {
      const decision = post([{ type: "text", text: STRIPE }]);
      assert.equal(verdict(decision), "block");
      assert.deepEqual(decision.hookSpecificOutput.updatedToolOutput, [{ type: "text", text: REDACTED }]);
      assert.ok(!JSON.stringify(decision).includes(STRIPE), "replacement must not echo the secret");
    }],
    ["scrub: clean result is allowed", () => {
      assert.equal(verdict(post({ stdout: "hello" })), "allow");
    }],
  ];

  const limitCases = [
    ["shell glob: cat secrets/*", () => {
      assert.equal(verdict(pre("Bash", { command: "cat secrets/*" })), "deny");
    }],
    ["base64 path: decoded after the hook", () => {
      assert.equal(
        verdict(pre("Bash", { command: "echo c2VjcmV0cy9hcGkta2V5LnR4dA== | base64 -d | xargs cat" })),
        "deny",
      );
    }],
    ["hardlink: innocent.txt -> secrets/api-key.txt", () => {
      assert.equal(verdict(pre("Read", { file_path: "innocent.txt" })), "deny");
    }],
    ["listing: a result naming private/ is not hidden", () => {
      assert.equal(verdict(post("private\nnotes.txt")), "block");
    }],
  ];

  for (const [name, testCase] of ruleCases) {
    try {
      testCase();
      rulePass += 1;
      console.log(`ok    ${name}`);
    } catch (error) {
      ruleFail += 1;
      console.log(`FAIL  ${name}`);
      console.log(`      ${failureSummary(error)}`);
    }
  }

  for (const [name, testCase] of limitCases) {
    try {
      testCase();
      limitsClosed += 1;
      console.log(`CLOSED ${name}`);
      console.log("       the hook now denies this; update README: The four limits");
    } catch (error) {
      limitsConfirmed += 1;
      console.log(`LIMIT ${name}`);
      console.log(`      secure expectation failed: ${failureSummary(error)}`);
    }
  }

  console.log(
    `\n${rulePass}/${ruleCases.length} rule cases passed; ` +
      `${limitsConfirmed}/${limitCases.length} limits confirmed as failures.`,
  );
  if (ruleFail || limitsClosed) process.exitCode = 1;
} finally {
  fs.rmSync(FIXTURE, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function setup() {
  fs.mkdirSync(path.join(FIXTURE, ".claude", "hooks"), { recursive: true });
  fs.copyFileSync(path.join(ROOT, ".agentignore"), path.join(FIXTURE, ".agentignore"));
  fs.copyFileSync(path.join(ROOT, "hooks", "agentignore.mjs"), HOOK);

  write("secrets/api-key.txt", `${STRIPE}\n`);
  write("private/notes.txt", "private notes\n");
  write(".env", "TOKEN=not-a-real-token\n");
  write("notes.txt", "hello\n");
  write(".claude/settings.json", "{}\n");
  write(".claude/settings.local.json", "{}\n");

  fs.linkSync(path.join(FIXTURE, "secrets", "api-key.txt"), path.join(FIXTURE, "innocent.txt"));
}

function write(relativePath, contents) {
  const target = path.join(FIXTURE, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function run(payload) {
  const result = spawnSync(process.execPath, [HOOK], {
    cwd: FIXTURE,
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: 20000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`hook exited ${result.status}: ${result.stderr.trim()}`);
  }
  const stdout = result.stdout.trim();
  return stdout ? JSON.parse(stdout) : null;
}

function pre(toolName, toolInput) {
  return run({
    hook_event_name: "PreToolUse",
    tool_name: toolName,
    tool_input: toolInput,
  });
}

function post(toolResponse) {
  return run({
    hook_event_name: "PostToolUse",
    tool_name: "Read",
    tool_input: {},
    tool_response: toolResponse,
  });
}

function verdict(decision) {
  if (!decision) return "allow";
  if (decision.hookSpecificOutput?.permissionDecision === "deny") return "deny";
  if (decision.decision === "block") return "block";
  return "other";
}

function failureSummary(error) {
  const lines = error.message.split("\n").map((line) => line.trim()).filter(Boolean);
  return lines.find((line) => line.includes("!==")) ?? lines[0] ?? error.name;
}
