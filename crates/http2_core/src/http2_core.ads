--  SPARK HTTP/2 frame layer.
--
--  Frame layouts and connection/stream state machine generated from
--  RecordFlux DSL specs under ``specs/`` into ``generated/``. HPACK
--  Huffman decoder and the (bounded) dynamic table are hand-written
--  SPARK and live here.
--
--  Subset for bare-metal use: single bidi stream, static HPACK,
--  no multiplexing, no priorities. Wire-compatible with standard
--  HTTP/2 peers.
package Http2_Core is

end Http2_Core;
