INSERT INTO	session (
  session_id,
  user,
  time_added,
  nas_ip,
  assigned_ip,
  client_ip,
  bytes_in,
  bytes_out,
  packets_in,
  packets_out,
  session_time
 ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0)