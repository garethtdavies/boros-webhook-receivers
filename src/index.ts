// Cloudflare Worker entry for the example Boros webhook receiver.
import { handleRequest, type ReceiverEnv } from "./receiver";

const worker = {
  fetch(request: Request, env: ReceiverEnv): Promise<Response> {
    return handleRequest(request, env);
  },
};

export default worker;
