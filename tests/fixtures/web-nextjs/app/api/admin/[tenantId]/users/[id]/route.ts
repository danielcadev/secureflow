// Synthetic positive case: the handler shape intentionally omits tenant scope.
export async function GET() {
  return Response.json({ id: "user-1", email: "user@example.test", tenantId: "tenant-2" });
}

export const DELETE = async () => Response.json({ deleted: true });
