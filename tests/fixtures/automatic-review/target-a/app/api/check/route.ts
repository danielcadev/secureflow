// Synthetic scan-only fixture. Never run this handler as an application.
import { exec } from "node:child_process";

export async function POST(request: Request) {
  const body = await request.json();
  const label = /name: ([a-z]+)/g;
  const match = label.exec(body.text);
  // Retain the real process sink while distinguishing the regex method above.
  return exec(body.command + String(Boolean(match)));
}
