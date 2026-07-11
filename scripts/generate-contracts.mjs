import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import openapiTS, { astToString } from "openapi-typescript";

const root = resolve(import.meta.dirname, "..");
const openapiPath = resolve(root, "docs/openapi-v1.json");
const typesPath = resolve(root, "apps/pwa/src/generated.ts");
const check = process.argv.includes("--check");

const openapi = execFileSync(
  "cargo",
  ["run", "--quiet", "-p", "blackspace-protocol", "--bin", "export-openapi"],
  { cwd: root, encoding: "utf8" },
).replaceAll("\r\n", "\n");
const ast = await openapiTS(JSON.parse(openapi));
const generated = `// Generated from crates/blackspace-protocol. Do not edit by hand.\n${astToString(ast)}`;

if (check) {
  const existingOpenapi = readFileSync(openapiPath, "utf8").replaceAll("\r\n", "\n");
  const existingTypes = readFileSync(typesPath, "utf8").replaceAll("\r\n", "\n");
  if (existingOpenapi !== openapi || existingTypes !== generated) {
    throw new Error("Generated protocol contracts are stale. Run `pnpm contracts:generate`.");
  }
} else {
  writeFileSync(openapiPath, openapi, "utf8");
  writeFileSync(typesPath, generated, "utf8");
}

