# Notes: gRPC over HTTP/2

Reading <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>.
Capturing what I'll need to implement.

## Request

```
:method      = POST
:scheme      = http | https
:path        = /<package>.<Service>/<Method>     ← case-sensitive
:authority   = host[:port]
te           = trailers                          ← required
content-type = application/grpc[+proto|+json]
grpc-timeout = <number><unit>                   (optional; H/M/S/m/u/n)
grpc-encoding = identity|gzip|deflate           (optional)
user-agent   = ...                              (optional)
```

Custom metadata follows. Binary metadata keys end with `-bin` and the value is
base64.

## Length-prefixed message frame (in DATA payload)

```
+--------+----------+----------+---------------------+
| 1 byte | 4 bytes  | 4 bytes  |    N bytes          |
| flag   |     length (BE)     |    message          |
+--------+----------+----------+---------------------+
```

- flag bit 0 = compressed (1) or not (0).
- length = byte length of the message that follows.
- HTTP/2 DATA frame boundaries are independent of message boundaries; a
  message may straddle multiple DATA frames or multiple messages may share
  one DATA frame.

## Response — normal

```
HEADERS  :status = 200
         content-type = application/grpc[+proto]
         grpc-encoding = identity|...               (optional)
         <custom response metadata>                 (optional)
DATA     <length-prefixed messages...>
HEADERS  grpc-status = <code>
         grpc-message = <urlencoded UTF-8>          (optional)
         <custom trailing metadata>                 (optional)
         END_STREAM
```

The trailing HEADERS frame is the trailer block. AWS doesn't currently emit
this — we'll add it.

## Response — Trailers-Only

When the server has only an error to return (or a unary OK with empty body),
it's allowed to collapse everything into one initial HEADERS frame:

```
HEADERS  :status = 200
         content-type = application/grpc
         grpc-status = <code>
         grpc-message = ...
         END_STREAM
```

## Status codes

16 codes plus OK (=0). Map to integers in the obvious way:

```
OK=0, CANCELLED=1, UNKNOWN=2, INVALID_ARGUMENT=3, DEADLINE_EXCEEDED=4,
NOT_FOUND=5, ALREADY_EXISTS=6, PERMISSION_DENIED=7, RESOURCE_EXHAUSTED=8,
FAILED_PRECONDITION=9, ABORTED=10, OUT_OF_RANGE=11, UNIMPLEMENTED=12,
INTERNAL=13, UNAVAILABLE=14, DATA_LOSS=15, UNAUTHENTICATED=16
```

HTTP/2 reset-stream codes also map to gRPC codes (REFUSED_STREAM →
UNAVAILABLE, etc.) — see the spec for the full table.

## What I'll need on the server side

1. Parse `:path`, dispatch to a registered service+method.
2. Read DATA frames, reassemble length-prefixed messages.
3. Decode protobuf into the request type.
4. Invoke the user's handler.
5. Encode the response, frame it, send DATA.
6. Send a trailer HEADERS frame with `grpc-status` (this is what AWS doesn't
   currently support).

## What I'll need on the client side

Mirror image. Build a request, send it, read response DATA + trailer HEADERS,
decode, return.

## Open questions

- What does AWS's HTTP/2 client surface for trailers? If it folds them into
  the response headers, we still get them but ordering may matter. If it
  drops them, we need another patch.
- What's the right thing for the server to do on `grpc-timeout`? Cancel the
  handler task? Send `DEADLINE_EXCEEDED`? Both, presumably.
