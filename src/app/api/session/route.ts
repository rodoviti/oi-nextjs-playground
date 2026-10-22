import { apiResponse, authenticate } from "@/lib/jwt";

export async function GET(request: Request) {
  return apiResponse(async () => Response.json((await authenticate(request)).session));
}
