// Local SMS capture — `bun run scripts/sms-capture.ts --port 38300`.
//
// The e2e run points the server's Twilio base at this host through the dev/CI-only
// `MONACA_SMS_PROVIDER_BASE_URL` override, so the real provider shape (form body + basic auth +
// `/2010-04-01/Accounts/<sid>/Messages.json`) is exercised without a Twilio account or network.

export interface CapturedSms {
  method: string;
  path: string;
  authorization: string | null;
  contentType: string | null;
  body: string;
}

export interface SmsCapture {
  baseUrl: string;
  requests: CapturedSms[];
  stop: () => void;
}

export function startSmsCapture(port: number): SmsCapture {
  const requests: CapturedSms[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    async fetch(request) {
      const url = new URL(request.url);
      requests.push({
        method: request.method,
        path: url.pathname,
        authorization: request.headers.get("authorization"),
        contentType: request.headers.get("content-type"),
        body: await request.text(),
      });
      return new Response(JSON.stringify({ sid: "SM_local_capture", status: "queued" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });
  return { baseUrl: `http://127.0.0.1:${port}`, requests, stop: () => server.stop(true) };
}

if (import.meta.main) {
  const port = Number(process.argv[process.argv.indexOf("--port") + 1] || 38300);
  const capture = startSmsCapture(port);
  console.log(`sms capture listening on ${capture.baseUrl}`);
}
