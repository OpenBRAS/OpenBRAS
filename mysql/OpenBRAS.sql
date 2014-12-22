CREATE DATABASE  IF NOT EXISTS `OpenBRAS` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `OpenBRAS`;
-- MySQL dump 10.13  Distrib 5.5.40, for debian-linux-gnu (x86_64)
--
-- Host: 127.0.0.1    Database: OpenBRAS
-- ------------------------------------------------------
-- Server version	5.5.40-0ubuntu0.14.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `Sessions`
--

DROP TABLE IF EXISTS `Sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Sessions` (
  `idSessions` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `idSubscriber` int(11) unsigned NOT NULL,
  `pppoeSession` smallint(5) unsigned NOT NULL,
  `subscriberMAC` bigint(20) unsigned NOT NULL,
  `subscriberIP` int(10) unsigned NOT NULL,
  `bytesReceived` bigint(20) unsigned NOT NULL DEFAULT '0',
  `bytesSent` bigint(20) unsigned NOT NULL DEFAULT '0',
  `timeStart` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `timeStop` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `active` tinyint(4) NOT NULL DEFAULT '1',
  PRIMARY KEY (`idSessions`),
  UNIQUE KEY `idSessions_UNIQUE` (`idSessions`),
  KEY `fk_Sessions_1_idx` (`idSubscriber`),
  CONSTRAINT `fk_Sessions_1` FOREIGN KEY (`idSubscriber`) REFERENCES `Subscribers` (`idSubscriber`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8 */ ;
/*!50003 SET character_set_results = utf8 */ ;
/*!50003 SET collation_connection  = utf8_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = '' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `Sessions_BUPD` BEFORE UPDATE ON `Sessions` FOR EACH ROW
BEGIN
	IF NEW.active = 0 THEN
		SET NEW.timeStop = now();
	END IF;
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `Subscribers`
--

DROP TABLE IF EXISTS `Subscribers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Subscribers` (
  `idSubscriber` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `subscriberUsername` varchar(45) NOT NULL,
  `subscriberPassword` varchar(45) NOT NULL,
  `subscriberState` enum('NEW','ACTIVE','CONFIGURE','CLOSED') NOT NULL DEFAULT 'NEW',
  `subscriberLastMAC` bigint(20) unsigned NOT NULL DEFAULT '0',
  `subscriberLastUpdate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `subscriberCreated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`idSubscriber`),
  UNIQUE KEY `idSubscribers_UNIQUE` (`idSubscriber`),
  UNIQUE KEY `SubscriberUsername_UNIQUE` (`subscriberUsername`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8 */ ;
/*!50003 SET character_set_results = utf8 */ ;
/*!50003 SET collation_connection  = utf8_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = '' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `Subscribers_BUPD` BEFORE UPDATE ON `Subscribers` FOR EACH ROW
SET NEW.SubscriberLastUpdate = now() */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Dumping routines for database 'OpenBRAS'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2014-12-22 15:20:17
