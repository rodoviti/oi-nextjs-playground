export function withoutSessionCookies(response: Response) {
  const headers = new Headers(response.headers);
  headers.delete("set-cookie");
  for (const cookie of response.headers.getSetCookie()) {
    if (!/^(?:__Secure-)?better-auth\.(?:session_token|session_data|account_data|dont_remember)(?:[.=])/.test(cookie)) {
      headers.append("set-cookie", cookie);
    }
  }
  return new Response(response.body, { status: response.status, headers });
}
