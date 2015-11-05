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

 Date: 11/05/2015 17:18:47 PM
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
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4;

-- ----------------------------
--  Records of `accounting`
-- ----------------------------
BEGIN;
INSERT INTO `accounting` VALUES ('1', 'user01', '2015-11-05 17:03', '1407', '467', 'Marks-MacBook-Air.local'), ('2', 'user01', '2015-11-05 17:05', '1407', '467', 'Marks-MacBook-Air.local'), ('3', 'user01', '2015-11-05 17:16', '4814', '1334', 'Marks-MacBook-Air.local');
COMMIT;

-- ----------------------------
--  Table structure for `session`
-- ----------------------------
DROP TABLE IF EXISTS `session`;
CREATE TABLE `session` (
  `session_id` int(10) unsigned NOT NULL,
  `user` varchar(100) NOT NULL,
  `time_added` int(10) unsigned NOT NULL,
  `nas_ip` varchar(50) NOT NULL,
  `hostname` varchar(50) NOT NULL,
  PRIMARY KEY (`session_id`,`user`,`nas_ip`),
  UNIQUE KEY `unique_session` (`user`,`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_login` (`user`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;

-- ----------------------------
--  Records of `user`
-- ----------------------------
BEGIN;
INSERT INTO `user` VALUES ('1', 'herp', 'derp', null, null);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
