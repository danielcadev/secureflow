declare const axios: {
  get(path: string): Promise<unknown>;
};

export async function loadFixtureData() {
  const userId = "fixture-user";
  await fetch("/api/health");
  await axios.get("/api/admin/acme/users/user-1");
  await fetch("/api/forgotten?from=client");
  await fetch("https://third-party.example/api/private");
  await fetch(`/api/users/${userId}`);
}

// fetch("/api/comment-decoy");
export const decoy = "fetch('/api/string-decoy')";
