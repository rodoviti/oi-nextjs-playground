import { apiResponse, authenticate } from "@/lib/jwt";

export async function GET(request: Request) {
  return apiResponse(async () => {
    const { session } = await authenticate(request);
    return Response.json({ message: "Accesso API autorizzato", sessionId: session.id, level: session.level });
  });
}
