import { apiResponse } from "@/lib/jwt";
import { generateMagicLink } from "@/lib/magic-link";

export async function POST(request: Request) {
  return apiResponse(async () => Response.json(await generateMagicLink(request)));
}
