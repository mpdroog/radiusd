/*
 Navicat Premium Data Transfer

 Source Server         : localhost
 Source Server Type    : MySQL
 Source Server Version : 50505
 Source Host           : localhost
 Source Database       : vpnxs_radius

 Target Server Type    : MySQL
 Target Server Version : 50505
 File Encoding         : utf-8

 Date: 12/03/2015 14:22:59 PM
*/

SET NAMES utf8;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `accounting`
-- ----------------------------
DROP TABLE IF EXISTS `accounting`;
CREATE TABLE `accounting` (
  `user` varchar(100) NOT NULL,
  `date` varchar(16) NOT NULL DEFAULT '' COMMENT '1min consolidated YYYY-MM-DD HH:MM',
  `hostname` varchar(50) NOT NULL COMMENT 'RadiusD-server for unique key',
  `bytes_in` bigint(15) unsigned NOT NULL COMMENT 'Octet in',
  `bytes_out` bigint(15) unsigned NOT NULL COMMENT 'Octet out',
  `packets_in` int(10) unsigned NOT NULL,
  `packets_out` int(10) unsigned NOT NULL,
  PRIMARY KEY (`user`,`date`,`hostname`),
  CONSTRAINT `fk_accounting_user` FOREIGN KEY (`user`) REFERENCES `user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
--  Table structure for `dns`
-- ----------------------------
DROP TABLE IF EXISTS `dns`;
CREATE TABLE `dns` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(10) NOT NULL,
  `dns_one` varchar(50) NOT NULL,
  `dns_two` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_name` (`name`),
  UNIQUE KEY `unique_dns` (`dns_one`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
--  Table structure for `product`
-- ----------------------------
DROP TABLE IF EXISTS `product`;
CREATE TABLE `product` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `product` varchar(50) NOT NULL,
  `simultaneous_use` int(10) unsigned NOT NULL COMMENT 'Max sessions',
  `ratelimit_up` int(10) unsigned DEFAULT NULL,
  `ratelimit_down` int(10) unsigned DEFAULT NULL,
  `ratelimit_unit` enum('k','M') DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_product` (`product`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
--  Table structure for `session`
-- ----------------------------
DROP TABLE IF EXISTS `session`;
CREATE TABLE `session` (
  `session_id` varchar(20) NOT NULL,
  `user` varchar(100) NOT NULL,
  `nas_ip` varchar(50) NOT NULL COMMENT 'VPN Server',
  `bytes_in` bigint(10) unsigned NOT NULL,
  `bytes_out` bigint(10) unsigned NOT NULL,
  `packets_in` bigint(10) unsigned NOT NULL,
  `packets_out` bigint(10) unsigned NOT NULL,
  `session_time` bigint(10) unsigned NOT NULL COMMENT 'Session open in sec',
  `client_ip` varchar(50) NOT NULL,
  `assigned_ip` varchar(50) NOT NULL,
  `time_added` int(10) unsigned NOT NULL,
  PRIMARY KEY (`session_id`,`user`,`nas_ip`),
  KEY `fk_session_user` (`user`),
  CONSTRAINT `fk_session_user` FOREIGN KEY (`user`) REFERENCES `user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Active connections.';

-- ----------------------------
--  Table structure for `session_log`
-- ----------------------------
DROP TABLE IF EXISTS `session_log`;
CREATE TABLE `session_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `bytes_in` bigint(10) unsigned NOT NULL,
  `bytes_out` bigint(10) unsigned NOT NULL,
  `packets_in` bigint(10) unsigned NOT NULL,
  `packets_out` bigint(10) unsigned NOT NULL,
  `session_id` varchar(20) NOT NULL,
  `session_time` bigint(10) unsigned NOT NULL COMMENT 'Session open in sec',
  `user` varchar(100) NOT NULL,
  `nas_ip` varchar(50) NOT NULL,
  `client_ip` varchar(50) NOT NULL,
  `assigned_ip` varchar(50) NOT NULL,
  `time_added` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_session_log_user` (`user`),
  CONSTRAINT `fk_session_log_user` FOREIGN KEY (`user`) REFERENCES `user` (`user`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Closed connections.';

-- ----------------------------
--  Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user` varchar(100) NOT NULL,
  `pass` varchar(255) NOT NULL,
  `block_remaining` bigint(20) unsigned DEFAULT NULL,
  `active_until` date NULL DEFAULT NULL COMMENT 'Account becomes inactive on given date',
  `dedicated_ip` varchar(50) DEFAULT NULL COMMENT 'Static IP',
  `product_id` int(10) unsigned NOT NULL,
  `dns_id` int(3) unsigned DEFAULT NULL COMMENT 'DNS Pri+Sec',
  `time_added` int(10) unsigned NOT NULL,
  `time_updated` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_login` (`user`),
  UNIQUE KEY `unique_ip` (`dedicated_ip`),
  KEY `fk_user_product` (`product_id`),
  KEY `fk_user_dns_1` (`dns_id`),
  CONSTRAINT `fk_user_dns_1` FOREIGN KEY (`dns_id`) REFERENCES `dns` (`id`),
  CONSTRAINT `fk_user_product` FOREIGN KEY (`product_id`) REFERENCES `product` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
