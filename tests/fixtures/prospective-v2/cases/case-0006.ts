export function mayRead(actorId: string, ownerId: string): boolean {
  return actorId.length > 0 && actorId === ownerId;
}
