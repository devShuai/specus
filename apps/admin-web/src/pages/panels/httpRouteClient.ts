export interface ClientIdentity {
  id: number | string;
  clientName: string;
}

export interface HttpRouteClientReference {
  clientId?: number | string | null;
  clientName: string;
}

/**
 * Resolve the client associated with an HTTP route.
 *
 * Some deployed server versions serialize identifiers differently or omit the
 * route clientId, while clientName remains present and unique. Prefer the ID,
 * then fall back to the persisted client name for compatibility.
 */
export function findHttpRouteClient<T extends ClientIdentity>(
  route: HttpRouteClientReference,
  clients: T[],
): T | undefined {
  if (route.clientId != null) {
    const routeClientId = String(route.clientId);
    const idMatch = clients.find((client) => String(client.id) === routeClientId);
    if (idMatch) {
      return idMatch;
    }
  }

  return clients.find((client) => client.clientName === route.clientName);
}
