--  Logger -- shared leveled logging for all crates.
--
--  Usage:
--    Logger.Log (Logger.Debug, "hs: state=" & State'Image (S));
--
--  Stripping for release builds:
--    All Log calls are stripped when Enable_Logging is False.
--    Set Enable_Logging := False in logger.ads or override via
--    build flag. The pragma Inline + constant boolean lets the
--    compiler dead-code-eliminate the call + string concatenation.

with Logger_Config;

package Logger is

   Enable_Logging : constant Boolean := Logger_Config.Enable_Logging;

   type Level is (Debug, Info, Warn, Error);

   Current_Level : Level := Debug;

   procedure Log (L : Level; Msg : String);
   pragma Inline (Log);

end Logger;
