INSERT INTO session_log (
  assigned_ip,
  bytes_in,
  bytes_out,
  client_ip,
  nas_ip,
  packets_in,
  packets_out,
  session_id,
  session_time,
  user,
  time_added
  )
SELECT
  assigned_ip,
  bytes_in,
  bytes_out,
  client_ip,
  nas_ip,
  packets_in,
  packets_out,
  session_id,
  session_time,
  user,
  time_added
FROM session
WHERE user = ?
  AND session_id = ?
  AND nas_ip = ?