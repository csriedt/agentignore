import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const HOOK_FILE = fileURLToPath(import.meta.url);
const WIN = process.platform === "win32";
const CASE = WIN ? "i" : "";

const FILE_TOOLS = new Set(["Read", "Write", "Edit", "MultiEdit", "NotebookEdit"]);
const SEARCH_TOOLS = new Set(["Grep", "Glob"]);
const SHELL_TOOLS = new Set(["Bash", "PowerShell", "shell"]);

const FILE_KEYS = ["file_path", "path", "notebook_path", "target_file", "target_directory", "directory"];
const SEARCH_KEYS = ["pattern", "path", "glob", "include"];
const SURFACE = [
  ".agentignore",
  "hooks/agentignore.mjs",
  ".claude/hooks/agentignore.mjs",
  ".claude/settings.json",
  ".claude/settings.local.json",
];
const REDACTED = "[blocked by .agentignore]";

main();

function main() {
  let payload;
  let policy;
  try {
    payload = JSON.parse(fs.readFileSync(0, "utf8"));
    policy = loadPolicy();
  } catch (error) {
    const reason = `agentignore could not load its policy: ${error.message}`;
    const postEvent = (payload?.hook_event_name ?? payload?.hookEventName) === "PostToolUse";
    const result = payload?.tool_response ?? payload?.tool_result ?? payload?.result ?? payload?.output ?? "";
    emit(postEvent ? block(reason, result) : deny(reason));
    return;
  }

  if ((payload.hook_event_name ?? payload.hookEventName) === "PostToolUse") {
    const decision = checkResult(payload, policy);
    if (decision) emit(decision);
    return;
  }

  const decision = checkToolUse(
    payload.tool_name ?? payload.toolName ?? "",
    payload.tool_input ?? payload.toolInput ?? {},
    policy,
  );
  if (decision) emit(decision);
}

function loadPolicy() {
  const lines = fs.readFileSync(path.join(process.cwd(), ".agentignore"), "utf8").split(/\r?\n/);
  const rules = [];
  const scrubs = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim() || line.trimStart().startsWith("#")) continue;

    const scrub = /^\s*scrub\s*:\s*(.+?)\s*$/i.exec(line);
    if (scrub) {
      try {
        scrubs.push({ line: index + 1, regex: new RegExp(scrub[1], "i") });
      } catch (error) {
        process.stderr.write(`.agentignore:${index + 1}: bad scrub regex: ${error.message}\n`);
      }
      continue;
    }

    rules.push(parsePathRule(line, index + 1));
  }

  return { rules, scrubs };
}

function parsePathRule(rawLine, lineNumber) {
  let source = rawLine.trim();
  let negated = false;

  if (source.startsWith("\\#") || source.startsWith("\\!")) {
    source = source.slice(1);
  } else if (source.startsWith("!")) {
    negated = true;
    source = source.slice(1);
  }

  source = source.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!source) throw new Error(`invalid path rule on line ${lineNumber}`);

  const anchored = source.startsWith("/") || source.includes("/");
  const body = source.replace(/^\//, "");
  const regex = new RegExp(`${anchored ? "^" : "(?:^|/)"}${globToRegex(body)}$`, CASE);
  return { negated, regex, source: body };
}

function globToRegex(glob) {
  let out = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") {
        out += "(?:.*/)?";
        index += 2;
      } else {
        out += ".*";
        index += 1;
      }
    } else if (char === "*") {
      out += "[^/]*";
    } else if (char === "?") {
      out += "[^/]";
    } else {
      out += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return out;
}

function isIgnored(relativePath, rules) {
  const parts = relativePath.split("/").filter(Boolean);
  for (let index = 0; index < parts.length; index += 1) {
    const subject = parts.slice(0, index + 1).join("/");
    let ignored = false;
    for (const rule of rules) {
      if (rule.regex.test(subject)) ignored = !rule.negated;
    }
    if (ignored) return true;
  }
  return false;
}

function isPolicySurface(relativePath) {
  const fold = (value) => (WIN ? value.toLowerCase() : value);
  const target = fold(relativePath);
  const hook = toRepoPath(HOOK_FILE);
  return [...SURFACE, hook].filter(Boolean).some((entry) => fold(entry) === target);
}

function toRepoPath(candidate) {
  const cleaned = String(candidate).trim().replace(/^[`"']+|[`"']+$/g, "");
  if (!cleaned || /^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned)) return "";
  const root = process.cwd();
  const relative = path.relative(root, path.resolve(root, cleaned));
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return "";
  return relative.split(path.sep).join("/");
}

function collectCandidates(toolName, input) {
  const known = FILE_TOOLS.has(toolName) ? FILE_KEYS : SEARCH_TOOLS.has(toolName) ? SEARCH_KEYS : null;
  const keys = known ?? [...FILE_KEYS, ...SEARCH_KEYS];
  const picked = keys.map((key) => input?.[key]).filter((value) => typeof value === "string" && value.trim());
  const scanned = scanPathTokens(flattenText(input));
  if (known) return picked.length ? picked : scanned;
  return [...picked, ...scanned];
}

function scanPathTokens(text) {
  const pattern = /(?:[A-Za-z]:)?[\\/]?(?:[\w@.~+-]+[\\/])+[\w@.~*+-]+|(?:^|[\s"'`([{=:])(\.[\w@.~+-]+)/g;
  const tokens = [];
  for (const match of text.matchAll(pattern)) {
    tokens.push(match[1] ?? match[0]);
  }
  return tokens.map((token) => token.replace(/\\/g, "/").replace(/^[`"'(]+|[`"'),;:.]+$/g, "")).filter(Boolean);
}

function checkToolUse(toolName, input, policy) {
  if (SHELL_TOOLS.has(toolName)) {
    return checkShell(typeof input.command === "string" ? input.command : "", policy);
  }

  for (const candidate of collectCandidates(toolName, input)) {
    const relativePath = toRepoPath(candidate);
    if (!relativePath) continue;
    if (isPolicySurface(relativePath)) {
      return deny(`${toolName} cannot access the agentignore policy surface: ${relativePath}.`);
    }
    if (isIgnored(relativePath, policy.rules)) {
      return deny(`${toolName} cannot access ${relativePath}: blocked by .agentignore.`);
    }
  }
  return null;
}

function literalNeedles(policy) {
  const rules = policy.rules
    .filter((rule) => !rule.negated && !/[*?[]/.test(rule.source))
    .map((rule) => rule.source);
  return [...new Set([...rules, ...SURFACE, toRepoPath(HOOK_FILE)].filter(Boolean))];
}

function checkShell(command, policy) {
  if (!command) return null;
  const text = command.replace(/\\/g, "/");
  const haystack = WIN ? text.toLowerCase() : text;

  for (const needle of literalNeedles(policy)) {
    const literal = WIN ? needle.toLowerCase() : needle;
    const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(^|[^\\w.-])${escaped}([^\\w.-]|$)`).test(haystack)) {
      return deny(`Blocked by .agentignore: the shell command names the protected path ${needle}.`);
    }
  }
  return null;
}

function flattenText(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(flattenText).filter(Boolean).join("\n");
  if (value && typeof value === "object") return Object.values(value).map(flattenText).filter(Boolean).join("\n");
  return "";
}

function redactValue(value, key = "") {
  if (typeof value === "string") return key === "type" ? value : REDACTED;
  if (Array.isArray(value)) return value.map((entry) => redactValue(entry));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entry]) => [entryKey, redactValue(entry, entryKey)]),
    );
  }
  return value;
}

function checkResult(payload, policy) {
  const result = payload.tool_response ?? payload.tool_result ?? payload.result ?? payload.output ?? "";
  const text = flattenText(result);
  if (!text) return null;

  for (const scrub of policy.scrubs) {
    if (scrub.regex.test(text)) {
      return block(
        `Tool result matched .agentignore scrub pattern on line ${scrub.line}. ` +
          "The whole result was replaced with a placeholder before model ingestion.",
        result,
      );
    }
  }
  return null;
}

function deny(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

function block(reason, result) {
  return {
    decision: "block",
    reason,
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      updatedToolOutput: redactValue(result),
    },
  };
}

function emit(decision) {
  process.stdout.write(`${JSON.stringify(decision)}\n`);
}
