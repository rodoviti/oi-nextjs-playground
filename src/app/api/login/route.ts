import { getAuth } from "@/auth";
import { withoutSessionCookies } from "@/lib/auth-response";
import { LOGIN_REQUEST_PATTERN } from "@/lib/login-response";
import { apiResponse, appOrigin, HttpError, readBody, requireBrowserOrigin } from "@/lib/jwt";

export async function POST(request: Request) {
  return apiResponse(async () => {
    await requireBrowserOrigin(request);
    const { level, requestId } = await readBody(request);
    if ((level !== "L2" && level !== "L3") || typeof requestId !== "string" || !LOGIN_REQUEST_PATTERN.test(requestId)) {
      throw new HttpError(400, "Livello o identificativo di login non validi");
    }
    const origin = await appOrigin();
    const response = await getAuth().api.signInSocial({
      headers: request.headers,
      asResponse: true,
      body: {
        provider: `spid-${level.toLowerCase()}`,
        callbackURL: `${origin}/auth/complete?requestId=${requestId}`,
        errorCallbackURL: `${origin}/auth/complete?requestId=${requestId}`,
        disableRedirect: true,
      },
    });
    return withoutSessionCookies(response);
  });
}
