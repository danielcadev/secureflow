import { resolve, sep } from "node:path";

export function projectPath(root: string, supplied: string): string | null {
  const base = resolve(root) + sep;
  const candidate = resolve(root, supplied);
  return candidate.startsWith(base) ? candidate : null;
}
