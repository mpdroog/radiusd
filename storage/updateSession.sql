UPDATE session SET
  bytes_in     = bytes_in + ?,
  bytes_out    = bytes_out + ?,
  packets_in   = packets_in + ?,
  packets_out  = packets_out + ?,
  session_time = ?
WHERE user = ?
  AND session_id = ?
  AND nas_ip = ?