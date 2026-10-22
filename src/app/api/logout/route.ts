import { apiResponse, authenticate, revokeSession } from "@/lib/jwt";

export async function POST(request: Request) {
  return apiResponse(async () => {
    const { session, expiresAt } = await authenticate(request, false);
    await revokeSession(session.id, expiresAt);
    return new Response(null, { status: 204 });
  });
}
