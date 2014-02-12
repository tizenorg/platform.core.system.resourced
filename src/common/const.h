#ifndef _RESMAN_CONST_H
#define _RESMAN_CONST_H

#define PATH_TO_NET_CGROUP_DIR "/sys/fs/cgroup/net_cls/"

#define TASK_FILE_NAME "/tasks"
#define CGROUP_FILE_NAME "/cgroup.procs"
#define CLASSID_FILE_NAME "/net_cls.classid"
#define UNKNOWN_APP "(unknown)"

#define THAWED_STATE "THAWED"

#define MAX_PATH_LENGTH 512
#define MAX_NAME_LENGTH 256

#define COMMA_DELIMETER ","

#define COUNTER_UPDATE_PERIOD 60
#define FLUSH_PERIOD 60

#define NONE_QUOTA_ID 0

#define API __attribute__((visibility("default")))

#define TIME_TO_SAFE_DATA 1 /* one second */

/*
 * @desc reserved classid enums
 * internal structure, we don't provide it externally
*/
enum resourced_reserved_classid {
	RESOURCED_UNKNOWN_CLASSID,
	RESOURCED_ALL_APP_CLASSID,		/**< kernel expects 1 for
						handling restriction for all
						applications  */
	RESOURCED_TETHERING_APP_CLASSID,	/**< it uses in user space logic
						for counting tethering traffic */
	RESOURCED_RESERVED_CLASSID_MAX,
};

enum resourced_counter_state {
	RESOURCED_DEFAULT_STATE = 0,
	RESOURCED_FORCIBLY_FLUSH_STATE = 1 << 1,
	RESOURCED_FORCIBLY_QUIT_STATE = 1 << 2,
	RESOURCED_NET_BLOCKED_STATE = 1 << 3,
};

#endif /* _RESMAN_CONST_H */
