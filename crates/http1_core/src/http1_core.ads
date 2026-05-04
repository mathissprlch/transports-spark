--  Http1_Core — minimal HTTP/1.1 server.
--
--  v0.3 scope per design.md: server-side only, single connection at a
--  time, request line + headers + Content-Length-based body, response
--  emitted as one HEADERS+body shot, Connection: close after every
--  response (no keep-alive, no pipelining). Chunked transfer encoding
--  and request/response streaming are v0.4.
--
--  Spec coverage: RFC 9112 §3 (Message Format), §4 (Transfer Codings,
--  Content-Length subset only), §6.1 (Field Lines, basic syntax — no
--  obs-fold). Wire parsing is hand-written rather than RFLX-modeled
--  because HTTP/1.1's text grammar (OWS, list field handling, header
--  case folding, etc.) maps poorly to RFLX's binary-message idioms.
--  Modeling the framing layer in RFLX is a v0.4 follow-up.

package Http1_Core is

   pragma Pure;

end Http1_Core;
