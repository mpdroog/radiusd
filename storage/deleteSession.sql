DELETE FROM	session
WHERE user = ?
  AND session_id = ?
  AND nas_ip = ?