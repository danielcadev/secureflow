export default function handler(_request: unknown, response: { json(value: unknown): void }) {
  response.json({ id: "legacy" });
}
