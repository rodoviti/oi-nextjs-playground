import { apiResponse, readBody } from "@/lib/jwt";
import { redeemMagicLink } from "@/lib/magic-link";

export async function POST(request: Request) {
  return apiResponse(async () => {
    const { jwe } = await readBody(request);
    return Response.json(await redeemMagicLink(jwe));
  });
}
