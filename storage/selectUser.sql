SELECT pass,
       block_remaining,
       active_until,
       1,
       simultaneous_use,
       dedicated_ip,
       CONCAT(ratelimit_up, ratelimit_unit, '/', ratelimit_down, ratelimit_unit),
       dns.one, dns.two
FROM      user
JOIN      product ON user.product_id = product.id
LEFT JOIN dns     ON user.dns_id     = dns.id
WHERE user = ?
