SELECT 1
FROM user
JOIN product ON user.product_id = product.id
WHERE user = ?