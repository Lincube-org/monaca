// Local SMTP capture — `bun run scripts/smtp-capture.ts --port 2525`.
//
// A minimal ESMTP server for the acceptance run: it answers EHLO/MAIL/RCPT/DATA and records the
// raw message, so SMTP delivery can be proven without a relay or an outbound network. It is
// deliberately plaintext: the production rule is that TLS is never downgraded, and the only
// plaintext endpoint the server accepts is a loopback host (this script).

export interface CapturedMail {
  from: string;
  to: string[];
  raw: string;
  receivedAt: string;
}

export interface SmtpCapture {
  port: number;
  messages: CapturedMail[];
  stop: () => void;
}

interface Session {
  buffer: string;
  data: boolean;
  raw: string;
  from: string;
  to: string[];
}

export function startSmtpCapture(port: number): SmtpCapture {
  const messages: CapturedMail[] = [];
  const sessions = new Map<unknown, Session>();

  const listen = Bun.listen({
    hostname: "127.0.0.1",
    port,
    socket: {
      open(socket) {
        sessions.set(socket, { buffer: "", data: false, raw: "", from: "", to: [] });
        socket.write("220 localhost ESMTP\r\n");
      },
      data(socket, chunk) {
        const session = sessions.get(socket);
        if (!session) return;
        session.buffer += new TextDecoder().decode(chunk);

        if (session.data) {
          const terminator = session.buffer.indexOf("\r\n.\r\n");
          if (terminator === -1) return;
          session.raw = session.buffer.slice(0, terminator);
          messages.push({
            from: session.from,
            to: [...session.to],
            raw: session.raw,
            receivedAt: new Date().toISOString(),
          });
          session.buffer = session.buffer.slice(terminator + 5);
          session.data = false;
          session.from = "";
          session.to = [];
          socket.write("250 2.0.0 queued\r\n");
        }

        while (!session.data) {
          const newline = session.buffer.indexOf("\r\n");
          if (newline === -1) return;
          const line = session.buffer.slice(0, newline);
          session.buffer = session.buffer.slice(newline + 2);
          const upper = line.toUpperCase();
          if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
            socket.write("250-localhost\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n");
          } else if (upper.startsWith("MAIL FROM:")) {
            session.from = line.slice(line.indexOf(":") + 1).trim();
            socket.write("250 2.1.0 ok\r\n");
          } else if (upper.startsWith("RCPT TO:")) {
            session.to.push(line.slice(line.indexOf(":") + 1).trim());
            socket.write("250 2.1.5 ok\r\n");
          } else if (upper === "DATA") {
            session.data = true;
            socket.write("354 end with <CRLF>.<CRLF>\r\n");
          } else if (upper === "QUIT") {
            socket.write("221 2.0.0 bye\r\n");
            socket.end();
          } else if (upper === "RSET") {
            socket.write("250 2.0.0 reset\r\n");
          } else {
            socket.write("250 2.0.0 ok\r\n");
          }
        }
      },
      close(socket) {
        sessions.delete(socket);
      },
      error(socket) {
        sessions.delete(socket);
      },
    },
  });

  return {
    port,
    messages,
    stop: () => {
      sessions.clear();
      listen.stop();
    },
  };
}

if (import.meta.main) {
  const port = Number(process.argv[process.argv.indexOf("--port") + 1] || 2525);
  const capture = startSmtpCapture(port);
  console.log(`smtp capture listening on 127.0.0.1:${capture.port}`);
}
