# vendor/

Third-party code we depend on, with our patches.

## aws/

A pinned clone of [AdaCore/aws](https://github.com/AdaCore/aws) plus the
trailer-emission patches needed for gRPC. Not committed directly — instead
we vendor it via a bootstrap script that clones the pinned upstream commit
and applies the patches in `aws-patches/`.

### Bootstrapping

```sh
./vendor/bootstrap.sh
```

This produces `vendor/aws/` as a regular directory (not a submodule) with
the patches applied on a local `grpc-ada` branch. Idempotent — re-running
fast-forwards if the upstream pin or patch set has changed.

### Why patches, not a submodule

The patches are small (~150 lines). Keeping them as `.patch` files in this
repo:
- makes the changes reviewable in code review,
- avoids dragging an entire AWS clone into our git history,
- gives us a clean PR-able artifact for upstreaming,
- lets us bump the upstream pin without losing local work.

If/when upstream merges them, we delete the patches and pin to a tagged
release.

## aws-patches/

Numbered unified diffs applied in order by `bootstrap.sh`. Each is
self-contained and individually reviewable:

- `0001-add-trailers-api.patch` — adds `AWS.Response.Set.Trailers` and
  read accessors. Pure additive change; default behavior preserved.
- `0002-http2-emit-trailer-headers.patch` — extends the HTTP/2 message
  writer to emit a trailer HEADERS frame after DATA when trailers are
  set on the response.
