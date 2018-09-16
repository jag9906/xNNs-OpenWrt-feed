/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * Portions copyright 2005-2016 Steinar H. Gunderson <sgunderson@bigfoot.com>.
 * Licensed under the same terms as the rest of Apache.
 *
 * Portions copyright 2008 Knut Auvor Grythe <knut@auvor.no>.
 * Licensed under the same terms as the rest of Apache.
 */

#define MPMITK_VERSION "2.4.7-04"

#include "config.h"

#include "apr.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"

# define _DBG(text,par...) \
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, \
                "(itkmpm: pid=%d uid=%d, gid=%d) %s(): " text, \
                getpid(), getuid(), getgid(), __FUNCTION__, par)

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <pwd.h>
#include <grp.h>

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"          /* for get_remote_host */
#include "http_connection.h"
#include "http_request.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "util_mutex.h"
#include "mpm_common.h"
#include "unixd.h"
#include "ap_listen.h"
#include "ap_mmn.h"
#include "apr_poll.h"
#include "ap_expr.h"

#include "seccomp.h"

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h> /* for bindprocessor() */
#endif

#include <signal.h>
#include <sys/times.h>

#if HAVE_LIBCAP
#include <sys/prctl.h>
#include <sys/capability.h>
#endif


/* config globals */

static uid_t ap_itk_min_uid=1;
static uid_t ap_itk_max_uid=UINT_MAX;
static gid_t ap_itk_min_gid=1;
static gid_t ap_itk_max_gid=UINT_MAX;

#if HAVE_LIBCAP
static int ap_itk_enable_caps=1;
#endif

module AP_MODULE_DECLARE_DATA mpm_itk_module;

#define UNSET_NICE_VALUE 100

typedef struct
{
    uid_t uid;
    gid_t gid;
    char *username;
    int nice_value;
    ap_expr_info_t *uid_expr;
    ap_expr_info_t *gid_expr;
} itk_per_dir_conf;

typedef struct
{
    int max_clients_vhost;
} itk_server_conf;

AP_DECLARE_DATA int ap_has_irreversibly_setuid = 0;

/* Only in use if not enabling capabilities. */
AP_DECLARE_DATA uid_t saved_unixd_uid = -1;
AP_DECLARE_DATA gid_t saved_unixd_gid = -1;

static int itk_pre_drop_privileges(apr_pool_t *pool, server_rec *s)
{
#if HAVE_LIBCAP
    if (ap_itk_enable_caps) {
        /* mod_unixd will drop down to a normal user. This means that even if an
         * attacker manage to execute code before setuid(), he/she cannot write to
         * files owned by uid 0, such as /etc/crontab. We'll need to keep our extra
         * privileges, though, since we need them for the actual query processing
         * later, so specify that we'll keep them across the setuid that is soon to
         * come.
         *
         * Note that since we still have CAP_SETUID, an attacker can setuid(0)
         * and get around this. Thus, we disallow setuid(0) if the platform
         * allows it.
         */
        restrict_setuid_range(ap_itk_min_uid, ap_itk_max_uid, ap_itk_min_gid, ap_itk_max_gid);
        if (prctl(PR_SET_KEEPCAPS, 1)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, errno, NULL, "prctl(PR_SET_KEEPCAPS, 1) failed");
            exit(APEXIT_CHILDFATAL);
        }
        return OK;
    }
#endif
    restrict_setuid_range(ap_itk_min_uid, ap_itk_max_uid, ap_itk_min_gid, ap_itk_max_gid);
    /* Fiddle with mod_unixd's structures so that it doesn't drop uid 0;
     * we need that, since we don't have capabilities.
     */
    saved_unixd_uid = ap_unixd_config.user_id;
    saved_unixd_gid = ap_unixd_config.group_id;
    ap_unixd_config.user_id = 0;
    ap_unixd_config.group_id = 0;
    return OK;
}

static int itk_post_drop_privileges(apr_pool_t *pool, server_rec *s)
{
#if HAVE_LIBCAP
    if (ap_itk_enable_caps) {
        cap_t caps;
        cap_value_t suidcaps[] = {
            CAP_SETUID,
            CAP_SETGID,
            CAP_DAC_READ_SEARCH,
            CAP_SYS_NICE,
        };

        /* We don't need to keep capabilities across setuid anymore, so stop that. */
        if (prctl(PR_SET_KEEPCAPS, 0)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, errno, NULL, "prctl(PR_SET_KEEPCAPS, 0) failed");
            exit(APEXIT_CHILDFATAL);
        }

        /* Now drop as many privileges as we can. We'll still
         * access files with uid=0, and we can setuid() to anything, but
         * at least there's tons of other evilness (like loading kernel
         * modules) we can't do directly. (The setuid() capability will
         * go away automatically when we setuid() or exec() -- the former
         * is likely to come first.)
         */
        caps = cap_init();
        cap_clear(caps);
        cap_set_flag(caps, CAP_PERMITTED, sizeof(suidcaps)/sizeof(cap_value_t), suidcaps, CAP_SET);
        cap_set_flag(caps, CAP_EFFECTIVE, sizeof(suidcaps)/sizeof(cap_value_t), suidcaps, CAP_SET);
        cap_set_proc(caps);
        cap_free(caps);
        return OK;
    }
#endif
    // Restore the configured unixd uid/gid.
    ap_unixd_config.user_id = saved_unixd_uid;
    ap_unixd_config.group_id = saved_unixd_gid;
    return OK;
}

static int have_forked = 0;

int itk_fork_process(conn_rec *c)
{
    if (have_forked) {
         return DECLINED;
    }

    pid_t pid = fork(), child_pid;
    int status;
    switch (pid) {
    case -1:
	ap_log_error(APLOG_MARK, APLOG_ERR, errno, NULL, "fork: Unable to fork new process");
	return HTTP_INTERNAL_SERVER_ERROR;
    case 0:
        /* Child; runs processing as usual, then dies.
         * This is a bit tricky in that we need to run ap_run_process_connection()
         * even though we are a process_connection hook ourselves! That is the only
         * way we can exit cleanly after the hook is done. Thus, we set have_forked
         * to signal that we don't want to end up in infinite recursion.
         */
        have_forked = 1;
        ap_close_listeners();
        ap_run_process_connection(c);
        ap_lingering_close(c);
	exit(0);
    default: /* parent; just wait for child to be done */
	do {
	    child_pid = waitpid(pid, &status, 0);
	} while (child_pid == -1 && errno == EINTR);

	if (child_pid != pid || !WIFEXITED(status)) {
	    if (WIFSIGNALED(status)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "child died with signal %u", WTERMSIG(status));
	    } else if (WEXITSTATUS(status) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, "child exited with non-zero exit status %u", WEXITSTATUS(status));
	    } else {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, NULL, "waitpid() failed");
	    }
	    exit(1);
	}

        /*
	 * It is important that ap_lingering_close() is called in the child
	 * and not here, since some modules (like mod_ssl) needs to know the state
	 * from earlier in the connection to be able to finish correctly.
	 * However, we close the socket itself here so that we don't keep a
	 * reference to it around, and then set the socket pointer to NULL so
	 * that when prefork tries to close it, it goes into early exit.
	 */
	apr_socket_close(ap_get_conn_socket(c));
	ap_set_core_module_config(c->conn_config, NULL);

        /* make sure the MPM does not process this connection */
	return OK;
    }
}

static int itk_init_handler(apr_pool_t *p, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *s)
{
    int threaded;
    int ret = ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded) != APR_SUCCESS;
    if (ret != APR_SUCCESS || threaded) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, ret, ptemp,
                      "mpm-itk cannot use threaded MPMs; please use prefork.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_add_version_component(p, "mpm-itk/" MPMITK_VERSION);
    return OK;
}

static int itk_post_perdir_config(request_rec *r)
{
    uid_t wanted_uid;
    gid_t wanted_gid;
    const char *wanted_username;
    int err = 0;

    itk_server_conf *sconf =
        (itk_server_conf *) ap_get_module_config(r->server->module_config, &mpm_itk_module);
    itk_per_dir_conf *dconf;

    /* Enforce MaxClientsVhost. */
    if (sconf->max_clients_vhost > 0) {
        worker_score *ws;
        char my_vhost[sizeof(ws->vhost)];
        apr_snprintf(my_vhost, sizeof(my_vhost), "%s:%d",
                     r->server->server_hostname,
                     r->connection->local_addr->port);

        int daemons_limit; 
        ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &daemons_limit);

        int i, num_other_servers = 0;
        for (i = 0; i < daemons_limit; ++i) {
            worker_score *ws = ap_get_scoreboard_worker_from_indexes(i, 0);
            if (ws->status >= SERVER_BUSY_READ && strcmp(ws->vhost, my_vhost) == 0)
                ++num_other_servers;
        }

        if (num_other_servers > sconf->max_clients_vhost) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, \
                "MaxClientsVhost reached for %s, refusing client.",
                my_vhost);
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }

    dconf = (itk_per_dir_conf *) ap_get_module_config(r->per_dir_config, &mpm_itk_module);
    if (dconf->nice_value != UNSET_NICE_VALUE &&
        setpriority(PRIO_PROCESS, 0, dconf->nice_value)) {
        _DBG("setpriority(): %s", strerror(errno));
        err = 1;
    }

    wanted_uid = dconf->uid;
    wanted_gid = dconf->gid;
    wanted_username = dconf->username;

    if (wanted_uid == -1 || wanted_gid == -1) {
        wanted_uid = ap_unixd_config.user_id;
        wanted_gid = ap_unixd_config.group_id;
        wanted_username = ap_unixd_config.user_name;
    }

    /* AssignUserIDExpr and AssignGroupIDExpr override AssignUserID and defaults. */
    if (dconf->uid_expr != NULL) {
      struct passwd *ent;
      const char *err;
      wanted_username = ap_expr_str_exec(r, dconf->uid_expr, &err);
      if (err) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, \
            "Error while parsing AssignUserIDExpr expression: %s",
            err);
        return HTTP_INTERNAL_SERVER_ERROR;
      }

      if (!(ent = getpwnam(wanted_username))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, \
            "AssignUserIDExpr returned '%s', which is not a valid user name",
            wanted_username);
        return HTTP_INTERNAL_SERVER_ERROR;
      }

      wanted_uid = ent->pw_uid;
    }
    if (dconf->gid_expr != NULL) {
      struct group *ent;
      const char *err;
      const char *wanted_groupname = ap_expr_str_exec(r, dconf->gid_expr, &err);
      if (err) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, \
            "Error while parsing AssignGroupIDExpr expression: %s",
            err);
        return HTTP_INTERNAL_SERVER_ERROR;
      }

      if (!(ent = getgrnam(wanted_groupname))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, \
            "AssignGroupIDExpr returned '%s', which is not a valid group name",
            wanted_groupname);
        return HTTP_INTERNAL_SERVER_ERROR;
      }

      wanted_gid = ent->gr_gid;
    }

    /* setuid() at least on the first request, but from there only if we need to change anything.
     * (Those requests will almost certainly fail.)
     */
    if ((!err && !ap_has_irreversibly_setuid) || wanted_uid != getuid() || wanted_gid != getgid()) {
        if (setgid(wanted_gid)) {
            _DBG("setgid(%d): %s", wanted_gid, strerror(errno));
            if (wanted_gid < ap_itk_min_gid || wanted_gid > ap_itk_max_gid) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                             "This is most likely due to the current LimitGIDRange setting.");
            }
            err = 1;
        } else if (initgroups(wanted_username, wanted_gid)) {
            _DBG("initgroups(%s, %d): %s", wanted_username, wanted_gid, strerror(errno));
            err = 1;
        } else if (setuid(wanted_uid)) {
            _DBG("setuid(%d): %s", wanted_uid, strerror(errno));
            if (wanted_uid < ap_itk_min_uid || wanted_uid > ap_itk_max_uid) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                             "This is most likely due to the current LimitUIDRange setting.");
            }
            err = 1;
        } else {
#if HAVE_LIBCAP
            if (ap_itk_enable_caps) {
                /* Drop our remaining privileges. Normally setuid() would do this
                 * for us, but since we were previously not uid 0 (just a normal
                 * user with CAP_SETUID), we need to do it ourselves.
                 */
                cap_t caps;
                caps = cap_init();
                cap_clear(caps);
                cap_set_proc(caps);
                cap_free(caps);
            }
#endif
            ap_has_irreversibly_setuid = 1;
        }
    }

    if (err) {
        if (ap_has_irreversibly_setuid) {
            /* Most likely a case of switching uid/gid within a persistent
             * connection; the RFCs allow us to just close the connection
             * at anytime, so we excercise our right. :-)
             */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, \
                "Couldn't set uid/gid/priority, closing connection.");
            ap_lingering_close(r->connection);
            exit(0);
        } else {
            /* Something went wrong even this is the first request.
             * We need to notify the user.
             */
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

/*
 * If we are in a persistent connection, we might end up in a state
 * where we can no longer read .htaccess files because we have already
 * setuid(). This can either be because the previous request was for
 * another vhost (basically the same problem as when setuid() fails in
 * itk.c), or it can be because a .htaccess file is readable only by
 * root.
 *
 * In any case, we don't want to give out a 403, since the request has
 * a very real chance of succeeding on a fresh connection (where
 * presumably uid=0). Thus, we give up serving the request on this
 * TCP connection, and do a hard close of the socket. As long as we're
 * in a persistent connection (and there _should_ not be a way this
 * would happen on the first request in a connection, save for subrequests,
 * which we special-case), this is allowed, as it is what happens on
 * a timeout. The browser will simply open a new connection and try
 * again (there's of course a performance hit, though, both due to
 * the new connection setup and the fork() of a new server child).
 */
static apr_status_t itk_dirwalk_stat(apr_finfo_t *finfo, request_rec *r,
                                     apr_int32_t wanted)
{
    apr_status_t status = apr_stat(finfo, r->filename, wanted, r->pool);
    if (ap_has_irreversibly_setuid && r->main == NULL && APR_STATUS_IS_EACCES(status)) {
         ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r,
                       "Couldn't read %s, closing connection.",
                       r->filename);
         ap_lingering_close(r->connection);
	 exit(0);
    }
    return status;
}

/* See itk_dirwalk_stat() for rationale. */
static apr_status_t itk_open_htaccess(request_rec *r,
                                      const char *dir_name, const char *access_name,
                                      ap_configfile_t **conffile, const char **full_name)
{
    int status;
         
    if (!ap_has_irreversibly_setuid || r->main != NULL) {
        return AP_DECLINED;
    }

    *full_name = ap_make_full_path(r->pool, dir_name, access_name);
    status = ap_pcfg_openfile(conffile, r->pool, *full_name);

    if (APR_STATUS_IS_EACCES(status)) {
         ap_log_rerror(APLOG_MARK, APLOG_WARNING, errno, r,
                       "Couldn't read %s, closing connection.",
                       *full_name);
         ap_lingering_close(r->connection);
	 exit(0);
    }
 
    return status;
}

static void itk_hooks(apr_pool_t *p)
{
    /* add our version component on init, and check that we are under prefork */
    ap_hook_post_config(itk_init_handler, NULL, NULL, APR_HOOK_MIDDLE);

    /* we need to hook into the privilege dropping both before and after mod_unixd */
    ap_hook_drop_privileges(itk_pre_drop_privileges, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_drop_privileges(itk_post_drop_privileges, NULL, NULL, APR_HOOK_LAST);

    /* fork just before ap_run_create_connection() is called */
    ap_hook_process_connection(itk_fork_process, NULL, NULL, APR_HOOK_REALLY_FIRST);

    /* set the uid as fast as possible, but not before merging per-dir config */
    ap_hook_post_perdir_config(itk_post_perdir_config, NULL, NULL, APR_HOOK_REALLY_FIRST);

    /* replace core_dirwalk_stat so that we can kill the connection on stat() failure */
    ap_hook_dirwalk_stat(itk_dirwalk_stat, NULL, NULL, APR_HOOK_MIDDLE);

    /* hook htaccess check so we can kill the connection on .htaccess open() failure */
    ap_hook_open_htaccess(itk_open_htaccess, NULL, NULL, APR_HOOK_REALLY_FIRST); 
}

static const char *assign_user_id (cmd_parms *cmd, void *ptr, const char *user_name, const char *group_name)
{
    itk_per_dir_conf *dconf = (itk_per_dir_conf *) ptr;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }

    dconf->username = apr_pstrdup(cmd->pool, user_name);
    dconf->uid = ap_uname2id(user_name);
    dconf->gid = ap_gname2id(group_name);
    return NULL;
}

static const char *limit_uid_range(cmd_parms *cmd, void *dummy, const char *min_arg, const char *max_arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_itk_min_uid = atoi(min_arg);
    ap_itk_max_uid = atoi(max_arg);
    return NULL;
}

static const char *limit_gid_range(cmd_parms *cmd, void *dummy, const char *min_arg, const char *max_arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_itk_min_gid = atoi(min_arg);
    ap_itk_max_gid = atoi(max_arg);
    return NULL;
}


#if HAVE_LIBCAP
static const char *enable_caps(cmd_parms *cmd, void *dummy, int arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_itk_enable_caps = arg;
    return NULL;
}
#endif

 
static const char *assign_user_id_expr (cmd_parms *cmd, void *ptr, const char *user_name_expr)
{
    itk_per_dir_conf *dconf = (itk_per_dir_conf *) ptr;

    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }

    dconf->uid_expr = ap_expr_parse_cmd_mi(cmd,
                                           user_name_expr,
                                           AP_EXPR_FLAG_STRING_RESULT,
                                           &err,
                                           NULL,
                                           AP_CORE_MODULE_INDEX);
    if (err) {
        return err;
    }

    return NULL;
}

static const char *assign_group_id_expr (cmd_parms *cmd, void *ptr, const char *group_name_expr)
{
    itk_per_dir_conf *dconf = (itk_per_dir_conf *) ptr;

    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err) {
        return err;
    }

    dconf->gid_expr = ap_expr_parse_cmd_mi(cmd,
                                           group_name_expr,
                                           AP_EXPR_FLAG_STRING_RESULT,
                                           &err,
                                           NULL,
                                           AP_CORE_MODULE_INDEX);
    if (err) {
        return err;
    }
    return NULL;
}

static const char *set_max_clients_vhost (cmd_parms *cmd, void *dummy, const char *arg)
{
    itk_server_conf *sconf =
        (itk_server_conf *) ap_get_module_config(cmd->server->module_config, &mpm_itk_module);
    sconf->max_clients_vhost = atoi(arg);
    return NULL;
}

static const char *set_nice_value (cmd_parms *cmd, void *ptr, const char *arg)
{
    itk_per_dir_conf *dconf = (itk_per_dir_conf *) ptr;
    int nice_value = atoi(arg);

    if (nice_value < -20) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "WARNING: NiceValue of %d is below -20, increasing NiceValue to -20.",
                     nice_value);
        nice_value = -20;
    }
    else if (nice_value > 19) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "WARNING: NiceValue of %d is above 19, lowering NiceValue to 19.",
                     nice_value);
        nice_value = 19;
    }
    dconf->nice_value = nice_value;
    return NULL;
}

static const command_rec itk_cmds[] = {
AP_INIT_TAKE2("AssignUserID", assign_user_id, NULL, RSRC_CONF|ACCESS_CONF,
              "Tie a virtual host to a specific child process."),
AP_INIT_RAW_ARGS("AssignUserIDExpr", assign_user_id_expr, NULL, RSRC_CONF|ACCESS_CONF,
                 "Choose user ID given an expression. Will override AssignUserID."),
AP_INIT_RAW_ARGS("AssignGroupIDExpr", assign_group_id_expr, NULL, RSRC_CONF|ACCESS_CONF,
                 "Choose group ID given an expression. Will override AssignUserID."),
AP_INIT_TAKE2("LimitUIDRange", limit_uid_range, NULL, RSRC_CONF,
              "If seccomp v2 is available (Linux 3.5.0+), limit the process's possible "
              "uid to the given range (inclusive endpoints)"),
AP_INIT_TAKE2("LimitGIDRange", limit_gid_range, NULL, RSRC_CONF,
              "If seccomp v2 is available (Linux 3.5.0+), limit the process's possible "
              "primary gid to the given range (inclusive endpoints). "
              "Note that this does not restrict supplemental gids!"),
#if HAVE_LIBCAP
AP_INIT_FLAG("EnableCapabilities", enable_caps, NULL, RSRC_CONF,
             "Drop most root capabilities in the parent process, and instead run as "
             "the user given by the User/Group directives with some extra capabilities "
             "(in particular setuid). Somewhat more secure, but can cause problems "
             "when serving from NFS."),
#endif
AP_INIT_TAKE1("MaxClientsVHost", set_max_clients_vhost, NULL, RSRC_CONF,
              "Maximum number of children alive at the same time for this virtual host."),
AP_INIT_TAKE1("NiceValue", set_nice_value, NULL, RSRC_CONF|ACCESS_CONF,
              "Set nice value for the given vhost, from -20 (highest priority) to 19 (lowest priority)."),
{ NULL }
};

/* == allocate a private per-dir config structure == */
static void *itk_create_dir_config(apr_pool_t *p, char *dummy)
{
    itk_per_dir_conf *c = (itk_per_dir_conf *)
        apr_pcalloc(p, sizeof(itk_per_dir_conf));
    c->uid = c->gid = -1;
    c->uid_expr = c->gid_expr = NULL;
    c->nice_value = UNSET_NICE_VALUE;
    return c;
}

/* == merge the parent per-dir config structure into ours == */
static void *itk_merge_dir_config(apr_pool_t *p, void *parent_ptr, void *child_ptr)
{
    itk_per_dir_conf *c = (itk_per_dir_conf *)
        itk_create_dir_config(p, NULL);
    itk_per_dir_conf *parent = (itk_per_dir_conf *) parent_ptr;
    itk_per_dir_conf *child = (itk_per_dir_conf *) child_ptr;

    if (child->username != NULL) {
      c->username = child->username;
      c->uid = child->uid;
      c->gid = child->gid;
    } else {
      c->username = parent->username;
      c->uid = parent->uid;
      c->gid = parent->gid;
    }
    if (child->uid_expr != NULL) {
      c->uid_expr = child->uid_expr;
    } else {
      c->uid_expr = parent->uid_expr;
    }
    if (child->gid_expr != NULL) {
      c->gid_expr = child->gid_expr;
    } else {
      c->gid_expr = parent->gid_expr;
    }
    if (child->nice_value != UNSET_NICE_VALUE) {
      c->nice_value = child->nice_value;
    } else {
      c->nice_value = parent->nice_value;
    }
    return c;
}

/* == allocate a private server config structure == */
static void *itk_create_server_config(apr_pool_t *p, server_rec *s)
{
    itk_server_conf *c = (itk_server_conf *)
        apr_pcalloc(p, sizeof(itk_server_conf));
    c->max_clients_vhost = -1;
    return c;
}

AP_DECLARE_MODULE(mpm_itk) = {
    STANDARD20_MODULE_STUFF,
    itk_create_dir_config,      /* create per-directory config structure */
    itk_merge_dir_config,       /* merge per-directory config structures */
    itk_create_server_config,   /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    itk_cmds,                   /* command apr_table_t */
    itk_hooks,                  /* register hooks */
};
