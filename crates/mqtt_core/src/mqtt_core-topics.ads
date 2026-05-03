--  Mqtt_Core.Topics — topic name vs topic-filter matching.
--
--  Source: MQTT Version 3.1.1 + Errata 01, OASIS Standard, 29 Oct 2014.
--  Section coverage: §4.7 — Topic Names and Topic Filters.
--
--  Wildcard rules (§4.7.1):
--    `+`  matches exactly one level (between two `/` or end of string).
--         Filter `home/+/temp` matches `home/kitchen/temp` but not
--         `home/kitchen/oven/temp` and not `home/temp`.
--    `#`  matches the rest of the topic, must be the LAST character
--         and preceded by `/` (or be the entire filter). Filter `#`
--         matches everything; `home/#` matches `home`, `home/x`,
--         `home/x/y`, etc.
--
--  Hand-written SPARK — RFLX models text protocols poorly, and topic
--  matching has dynamic-length compares + cross-character logic that
--  doesn't fit RecordFlux.

package Mqtt_Core.Topics
with SPARK_Mode
is

   --  True iff topic `Name` matches filter `Filter` per §4.7.1.
   function Matches (Name : String; Filter : String) return Boolean;

end Mqtt_Core.Topics;
