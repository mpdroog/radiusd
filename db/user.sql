CREATE USER 'radiusd'@'localhost' IDENTIFIED BY 'supersecretpassword';
GRANT USAGE ON *.* TO 'radiusd'@'localhost' IDENTIFIED BY 'supersecretpassword';
GRANT INSERT,SELECT,UPDATE ON vpnxs_radius.* TO 'radiusd'@'localhost';
GRANT INSERT,SELECT,UPDATE,DELETE ON vpnxs_radius.session TO 'radiusd'@'localhost';
FLUSH PRIVILEGES;