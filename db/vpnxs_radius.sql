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

 Date: 11/09/2015 15:22:52 PM
*/

SET NAMES utf8;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
--  Table structure for `accounting`
-- ----------------------------
DROP TABLE IF EXISTS `accounting`;
CREATE TABLE `accounting` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user` varchar(100) NOT NULL,
  `date` varchar(16) NOT NULL DEFAULT '' COMMENT '5min consolidated YYYY-MM-DD HH:MM',
  `bytes_in` bigint(15) NOT NULL COMMENT 'Octet in',
  `bytes_out` bigint(15) NOT NULL COMMENT 'Octet out',
  `hostname` varchar(50) NOT NULL COMMENT 'RadiusD-server for unique key',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_acct` (`user`,`date`,`hostname`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4;

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
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

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
  UNIQUE KEY `unique_session` (`user`)
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
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COMMENT='Closed connections.';

-- ----------------------------
--  Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user` varchar(100) NOT NULL,
  `pass` varchar(255) NOT NULL,
  `block_remaining` bigint(20) unsigned DEFAULT NULL,
  `active_until` timestamp NULL DEFAULT NULL COMMENT 'Account becomes inactive on given date',
  `dedicated_ip` varchar(50) DEFAULT NULL COMMENT 'Static IP',
  `product_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_login` (`user`),
  UNIQUE KEY `unique_ip` (`dedicated_ip`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
