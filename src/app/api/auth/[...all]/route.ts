import { getAuth } from "@/auth";
import { apiResponse, HttpError, publicJwks } from "@/lib/jwt";
import { withoutSessionCookies } from "@/lib/auth-response";

export async function GET(request: Request) {
  return apiResponse(async () => {
    const path = new URL(request.url).pathname;
    if (path === "/api/auth/jwks") return Response.json(await publicJwks());
    if (!/^\/api\/auth\/callback\/spid-l[23]$/.test(path)) {
      throw new HttpError(404, "Endpoint non disponibile");
    }
    return withoutSessionCookies(await getAuth().handler(request));
  });
}
