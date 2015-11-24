network_db_version="`sqlite3 /opt/usr/dbspace/.resourced-datausage.db "PRAGMA user_version;"`"

if [ 0"$network_db_version" -eq 1 ]
then
    echo "user_version PRAGMA is 1. No need to run this script"
    exit 1
fi

sqlite3 /opt/usr/dbspace/.resourced-datausage.db "
PRAGMA journal_mode=PERSIST;
DROP TABLE IF EXISTS fota;
ALTER TABLE statistics RENAME to fota;
CREATE TABLE IF NOT EXISTS statistics (
  binpath TEXT,
  received BIGINT,
  sent BIGINT,
  time_stamp BIGINT,
  iftype INT,
  is_roaming INT,
  hw_net_protocol_type INT,
  ifname TEXT,
  reserved TEXT,
  imsi TEXT,
  ground INT DEFAULT 0,
  PRIMARY KEY (binpath, time_stamp, iftype, imsi)
);
INSERT INTO statistics (binpath, received, sent, time_stamp, iftype, is_roaming,
hw_net_protocol_type, ifname, reserved, imsi) SELECT binpath, received, sent, time_stamp, iftype, is_roaming,
hw_net_protocol_type, ifname, reserved, imsi from fota;
DROP TABLE IF EXISTS fota;
"
sqlite3 /opt/usr/dbspace/.resourced-datausage.db "
PRAGMA journal_mode=PERSIST;
DROP TABLE IF EXISTS fota;
ALTER TABLE quotas RENAME to fota;
CREATE TABLE IF NOT EXISTS quotas (
  binpath TEXT,
  sent_quota BIGINT,
  rcv_quota BIGINT,
  snd_warning_threshold INT,
  rcv_warning_threshold INT,
  time_period BIGINT,
  start_time BIGINT,
  iftype INT,
  roaming INT,
  reserved TEXT,
  imsi TEXT,
  ground INT DEFAULT 0,
  PRIMARY KEY(binpath, iftype, roaming, imsi, ground)
);
INSERT INTO quotas (binpath, sent_quota, rcv_quota, snd_warning_threshold, rcv_warning_threshold, time_period,
start_time, iftype, roaming, reserved, imsi) SELECT binpath, sent_quota, rcv_quota, snd_warning_threshold, rcv_warning_threshold, time_period,
start_time, iftype, roaming, reserved, imsi from fota;
DROP TABLE IF EXISTS fota;
"

sqlite3 /opt/usr/dbspace/.resourced-datausage.db "
PRAGMA journal_mode=PERSIST;
DROP TABLE IF EXISTS fota;
ALTER TABLE restrictions RENAME to fota;
CREATE TABLE IF NOT EXISTS restrictions (
binpath TEXT,
rcv_limit BIGINT,
send_limit BIGINT,
iftype INT,
rst_state INT,
quota_id INT,
roaming INT,
reserved TEXT,
ifname TEXT,
imsi TEXT DEFAULT 'noneimsi',
PRIMARY KEY (binpath, iftype, ifname, quota_id, imsi)
);
INSERT INTO restrictions (binpath, rcv_limit, send_limit, iftype, rst_state, quota_id,
roaming, reserved, ifname) SELECT binpath, rcv_limit, send_limit, iftype, rst_state, quota_id,
roaming, reserved, ifname from fota;

INSERT INTO restrictions VALUES('com.samsung.easysignup', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.osmeta.runtime', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.osmeta.runtime.service', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.email', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-composer-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-viewer-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-conversation-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-mailbox-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-account-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-filter-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-block-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-locker-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('email-setting-efl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.email-misc_worker', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.email-record-video-icon', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.samsungaccount', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.samsungaccount.samsungaccountservice', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.samsungaccount.samsungaccountpushefl', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.samsungaccount.samsungaccountupdate', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.special-day-app', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.special-day-widget', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.tizenstore.billingagent', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.inapppurchase', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.inapppurchase.iapclient', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.inapppurchase.iapservice', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.tizenstore', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.tizenstoreservice', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.videos-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.video-player-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('org.tizen.webcontainer', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.themestore', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('ACL111OMWW.AclService', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('ACL111OMWW.AclManager', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('ACL111OMWW.AclAudioProxyService', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.gallery-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('gallery-efl-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.gallery-lite.appcontrol', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.image-viewer.appcontrol.slideshow', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.image-viewer', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.image-viewer-subapp', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.image-viewer-subapp-single', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('image-viewer-efl-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.gallery-lite.dbox', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.music-player-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.sound-player-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.music-chooser-lite', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.music-player-lite.widget', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
INSERT INTO restrictions VALUES('com.samsung.cloud-content-sync', 0, 0, 1, 3, 0, 2, '', 'seth_w0', 'noneimsi');
DROP TABLE IF EXISTS fota;
"
