/*
 * pam_authelia.c - PAM module for Authelia SSH authentication.
 *
 * This is a thin shim that handles PAM conversation (prompting) and delegates
 * all authentication logic to the pam_authelia Go binary via a stdin/stdout
 * pipe protocol.
 *
 * Copyright 2024 Authelia Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#define __STDC_WANT_LIB_EXT1__ 1
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#endif

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef PAM_AUTHELIA_VERSION
#define PAM_AUTHELIA_VERSION "0.0.0-dev"
#endif

#if defined(__ELF__)
#define PAM_AUTHELIA_VERSION_ATTR __attribute__((used, section(".rodata")))
#else
#define PAM_AUTHELIA_VERSION_ATTR __attribute__((used))
#endif

static const char pam_authelia_version[] PAM_AUTHELIA_VERSION_ATTR =
    "pam_authelia/" PAM_AUTHELIA_VERSION;

#include "pam_authelia.h"

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/* Wipe memory in a way the compiler can't elide. */
static void
secure_clear(void *ptr, size_t len)
{
#if defined(__APPLE__)
	memset_s(ptr, len, 0, len);
#elif defined(__linux__) || defined(__FreeBSD__)
	explicit_bzero(ptr, len);
#else
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (len--) {
		*p++ = 0;
	}
#endif
}

/* Send a single message via the PAM conversation function. Caller owns the
 * returned response string when `response` is non-NULL. */
static int
authelia_pam_prompt(pam_handle_t *pamh, int msg_style, const char *prompt_text, char **response)
{
	const struct pam_conv *conv = NULL;
	struct pam_message msg;
	const struct pam_message *msgp = &msg;
	struct pam_response *resp = NULL;
	int ret;

	ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (ret != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
		return PAM_CONV_ERR;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_style = msg_style;
	msg.msg = (char *)prompt_text;

	ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
	if (ret != PAM_SUCCESS) {
		if (resp != NULL) {
			if (resp->resp != NULL) {
				secure_clear(resp->resp, strlen(resp->resp));
				free(resp->resp);
			}
			free(resp);
		}
		return ret;
	}

	if (response != NULL) {
		if (resp != NULL && resp->resp != NULL) {
			*response = resp->resp;
			resp->resp = NULL; /* Transfer ownership. */
		} else {
			*response = NULL;
		}
	}

	if (resp != NULL) {
		free(resp);
	}

	return PAM_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

static void
config_init(struct pam_authelia_config *cfg)
{
	cfg->binary              = PAM_AUTHELIA_DEFAULT_BINARY;
	cfg->url                 = NULL;
	cfg->auth_level          = "1FA+2FA";
	cfg->cookie_name         = "authelia_session";
	cfg->ca_cert             = NULL;
	cfg->method_priority     = NULL;
	cfg->oauth2_client_id    = NULL;
	cfg->oauth2_client_secret = NULL;
	cfg->oauth2_scope        = NULL;
	cfg->timeout             = PAM_AUTHELIA_DEFAULT_TIMEOUT;
	cfg->debug               = 0;
}

static int
config_parse(struct pam_authelia_config *cfg, int argc, const char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "url=", 4) == 0) {
			cfg->url = argv[i] + 4;
		} else if (strncmp(argv[i], "auth-level=", 11) == 0) {
			cfg->auth_level = argv[i] + 11;
		} else if (strncmp(argv[i], "cookie-name=", 12) == 0) {
			cfg->cookie_name = argv[i] + 12;
		} else if (strncmp(argv[i], "ca-cert=", 8) == 0) {
			cfg->ca_cert = argv[i] + 8;
		} else if (strncmp(argv[i], "timeout=", 8) == 0) {
			cfg->timeout = atoi(argv[i] + 8);
			if (cfg->timeout <= 0) {
				cfg->timeout = PAM_AUTHELIA_DEFAULT_TIMEOUT;
			}
		} else if (strncmp(argv[i], "binary=", 7) == 0) {
			cfg->binary = argv[i] + 7;
		} else if (strncmp(argv[i], "method-priority=", 16) == 0) {
			cfg->method_priority = argv[i] + 16;
		} else if (strncmp(argv[i], "oauth2-client-id=", 17) == 0) {
			cfg->oauth2_client_id = argv[i] + 17;
		} else if (strncmp(argv[i], "oauth2-client-secret=", 21) == 0) {
			cfg->oauth2_client_secret = argv[i] + 21;
		} else if (strncmp(argv[i], "oauth2-scope=", 13) == 0) {
			cfg->oauth2_scope = argv[i] + 13;
		} else if (strcmp(argv[i], "debug") == 0) {
			cfg->debug = 1;
		}
	}

	if (cfg->url == NULL) {
		return -1;
	}

	return 0;
}

/* -------------------------------------------------------------------------- */
/* Pipe I/O                                                                   */
/* -------------------------------------------------------------------------- */

/* Write `line` followed by '\n', retrying short writes and EINTR. */
static int
write_line(int fd, const char *line)
{
	size_t len = strlen(line);
	ssize_t n;

	while (len > 0) {
		n = write(fd, line, len);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		line += n;
		len -= (size_t)n;
	}

	while (1) {
		n = write(fd, "\n", 1);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		break;
	}

	return 0;
}

static time_t
monotonic_seconds(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return time(NULL);
	}
	return ts.tv_sec;
}

/* Seconds → milliseconds for poll(2), clamped to [0, INT_MAX]. */
static int
clamp_poll_ms(time_t seconds)
{
	if (seconds <= 0) {
		return 0;
	}

	long long ms = (long long)seconds * 1000LL;
	if (ms > (long long)INT_MAX) {
		return INT_MAX;
	}

	return (int)ms;
}

/* Read until '\n' or EOF, capped at bufsz-1 bytes. Returns 0 on success,
 * -1 on EOF/error, 1 on deadline. */
static int
read_line(int fd, char *buf, size_t bufsz, time_t deadline)
{
	size_t pos = 0;
	ssize_t n;
	char c;

	while (pos < bufsz - 1) {
		time_t now = monotonic_seconds();
		if (now >= deadline) {
			return 1;
		}

		struct pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN;

		int pr = poll(&pfd, 1, clamp_poll_ms(deadline - now));
		if (pr < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (pr == 0) {
			return 1;
		}

		n = read(fd, &c, 1);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (n == 0) {
			if (pos == 0) return -1;
			break;
		}
		if (c == '\n') {
			break;
		}
		buf[pos++] = c;
	}

	buf[pos] = '\0';
	return 0;
}

/* Read exactly `want` bytes — used for the length-prefixed PROMPT_MULTI_VISIBLE
 * payload, whose contents may contain newlines. Same return codes as read_line. */
static int
read_bytes(int fd, char *buf, size_t want, time_t deadline)
{
	size_t pos = 0;

	while (pos < want) {
		time_t now = monotonic_seconds();
		if (now >= deadline) {
			return 1;
		}

		struct pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN;

		int pr = poll(&pfd, 1, clamp_poll_ms(deadline - now));
		if (pr < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (pr == 0) {
			return 1;
		}

		ssize_t n = read(fd, buf + pos, want - pos);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (n == 0) {
			return -1;
		}

		pos += (size_t)n;
	}

	return 0;
}

#ifdef __linux__
/* -------------------------------------------------------------------------- */
/* Client disconnect detection                                                */
/* -------------------------------------------------------------------------- */

/* Compare a peer address against PAM_RHOST. */
static int
addr_matches_rhost(const struct sockaddr_storage *addr, const char *rhost)
{
	char peer[INET6_ADDRSTRLEN];

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		if (inet_ntop(AF_INET, &sin->sin_addr, peer, sizeof(peer)) == NULL) {
			return 0;
		}

		return strcmp(peer, rhost) == 0;
	}

	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		if (inet_ntop(AF_INET6, &sin6->sin6_addr, peer, sizeof(peer)) == NULL) {
			return 0;
		}

		/* Literal match first (covers native IPv6 + IPv4-mapped on both sides). */
		if (strcmp(peer, rhost) == 0) {
			return 1;
		}

		/* sshd often sets PAM_RHOST to the bare IPv4 form for ::ffff:1.2.3.4
		 * peers, so also try the stripped version. */
		if (strncmp(peer, "::ffff:", 7) == 0 && strcmp(peer + 7, rhost) == 0) {
			return 1;
		}

		return 0;
	}

	return 0;
}

/* Walk /proc/self/fd for the AF_INET/AF_INET6 socket whose peer matches
 * PAM_RHOST. Returns sshd's fd (do not close) or -1 if not found. */
static int
find_client_socket(pam_handle_t *pamh)
{
	const char *rhost = NULL;
	if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) != PAM_SUCCESS ||
	    rhost == NULL || rhost[0] == '\0') {
		return -1;
	}

	DIR *dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		return -1;
	}

	int found = -1;
	struct dirent *entry;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
			continue;
		}

		int fd = atoi(entry->d_name);
		if (fd < 0) {
			continue;
		}

		struct stat st;
		if (fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode)) {
			continue;
		}

		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);
		if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) != 0) {
			continue;
		}

		if (addr_matches_rhost(&addr, rhost)) {
			found = fd;
			break;
		}
	}

	closedir(dir);
	return found;
}

#define WAIT_CMD_READY     0
#define WAIT_CLIENT_GONE   1
#define WAIT_DEADLINE      2
#define WAIT_ERROR        -1

/* Block until the command pipe is readable, the client socket disconnects, or
 * the deadline expires. client_fd < 0 disables disconnect monitoring. */
static int
wait_for_event(int cmd_fd, int client_fd, time_t deadline)
{
	while (1) {
		time_t now = monotonic_seconds();
		if (now >= deadline) {
			return WAIT_DEADLINE;
		}

		struct pollfd pfds[2];
		nfds_t nfds = 1;

		pfds[0].fd = cmd_fd;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;

		if (client_fd >= 0) {
			pfds[1].fd = client_fd;
			pfds[1].events = POLLRDHUP;
			pfds[1].revents = 0;
			nfds = 2;
		}

		int pr = poll(pfds, nfds, clamp_poll_ms(deadline - now));
		if (pr < 0) {
			if (errno == EINTR) continue;
			return WAIT_ERROR;
		}
		if (pr == 0) {
			return WAIT_DEADLINE;
		}

		if (nfds == 2 && (pfds[1].revents &
		    (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL))) {
			return WAIT_CLIENT_GONE;
		}

		if (pfds[0].revents & POLLIN) {
			return WAIT_CMD_READY;
		}

		if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
			return WAIT_ERROR;
		}
	}
}
#endif /* __linux__ */

/* -------------------------------------------------------------------------- */
/* PAM module entry point.                                                    */
/* -------------------------------------------------------------------------- */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct pam_authelia_config cfg;
	const char *username = NULL;
	const char *authtok = NULL;
	pid_t child;
	int pipe_to_child[2];   /* Parent writes, child reads (child's stdin).  */
	int pipe_from_child[2]; /* Child writes, parent reads (child's stdout). */
	int status;
	int ret = PAM_AUTH_ERR;
	char line[MAX_LINE];

	(void)flags;

	config_init(&cfg);
	if (config_parse(&cfg, argc, argv) != 0) {
		return PAM_AUTH_ERR;
	}

	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
		return PAM_AUTH_ERR;
	}

	if (pipe(pipe_to_child) != 0) {
		return PAM_AUTH_ERR;
	}
	if (pipe(pipe_from_child) != 0) {
		close(pipe_to_child[0]);
		close(pipe_to_child[1]);
		return PAM_AUTH_ERR;
	}

	child = fork();
	if (child < 0) {
		close(pipe_to_child[0]);
		close(pipe_to_child[1]);
		close(pipe_from_child[0]);
		close(pipe_from_child[1]);
		return PAM_AUTH_ERR;
	}

	if (child == 0) {
		/* ---- Child process ---- */
		close(pipe_to_child[1]);
		close(pipe_from_child[0]);

		if (dup2(pipe_to_child[0], STDIN_FILENO) < 0 ||
		    dup2(pipe_from_child[1], STDOUT_FILENO) < 0) {
			_exit(1);
		}

		close(pipe_to_child[0]);
		close(pipe_from_child[1]);

#ifdef __linux__
		/* Get SIGTERM if sshd dies mid-auth so device-auth polling can't outlive
		 * the SSH session and keep hammering the Authelia API. */
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		/* PR_SET_PDEATHSIG is a no-op if the parent already exited between
		 * fork() and now; guard explicitly. */
		if (getppid() == 1) {
			_exit(1);
		}
#endif

		/* APPEND_ARG bounds-checks every write so the array can't overflow if
		 * options are added later. The trailing NULL needs a slot too. */
		char timeout_str[16];
		snprintf(timeout_str, sizeof(timeout_str), "%d", cfg.timeout);

		char *args[MAX_ARGS];
		int ai = 0;

#define APPEND_ARG(value) do {                            \
			if (ai >= MAX_ARGS - 1) { _exit(1); }         \
			args[ai++] = (char *)(value);                 \
		} while (0)

		APPEND_ARG(cfg.binary);
		APPEND_ARG("--url");
		APPEND_ARG(cfg.url);
		APPEND_ARG("--auth-level");
		APPEND_ARG(cfg.auth_level);
		APPEND_ARG("--cookie-name");
		APPEND_ARG(cfg.cookie_name);
		APPEND_ARG("--timeout");
		APPEND_ARG(timeout_str);

		if (cfg.ca_cert != NULL) {
			APPEND_ARG("--ca-cert");
			APPEND_ARG(cfg.ca_cert);
		}

		if (cfg.method_priority != NULL) {
			APPEND_ARG("--method-priority");
			APPEND_ARG(cfg.method_priority);
		}

		if (cfg.oauth2_client_id != NULL) {
			APPEND_ARG("--oauth2-client-id");
			APPEND_ARG(cfg.oauth2_client_id);
		}

		if (cfg.oauth2_client_secret != NULL) {
			APPEND_ARG("--oauth2-client-secret");
			APPEND_ARG(cfg.oauth2_client_secret);
		}

		if (cfg.oauth2_scope != NULL) {
			APPEND_ARG("--oauth2-scope");
			APPEND_ARG(cfg.oauth2_scope);
		}

		if (cfg.debug) {
			APPEND_ARG("--debug");
		}

#undef APPEND_ARG

		args[ai] = NULL;

		execv(cfg.binary, args);
		_exit(127);
	}

	/* ---- Parent process ---- */
	close(pipe_to_child[0]);
	close(pipe_from_child[1]);

	if (write_line(pipe_to_child[1], username) != 0) {
		goto cleanup;
	}

	/* Pull the password from PAM_AUTHTOK if a preceding module already prompted
	 * for it; otherwise prompt ourselves. When method-priority starts with
	 * device_authorization the device flow is self-contained, so we send an
	 * empty placeholder to keep the protocol in sync without prompting. */
	int device_first = 0;
	if (cfg.method_priority != NULL && strncmp(cfg.method_priority, "device_authorization", 20) == 0) {
		char next = cfg.method_priority[20];
		device_first = (next == '\0' || next == ',');
	}

	if (device_first) {
		if (write_line(pipe_to_child[1], "") != 0) {
			goto cleanup;
		}
	} else if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok) == PAM_SUCCESS && authtok != NULL) {
		if (write_line(pipe_to_child[1], authtok) != 0) {
			goto cleanup;
		}
	} else {
		char *pw = NULL;
		if (authelia_pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, "Password: ", &pw) != PAM_SUCCESS || pw == NULL) {
			goto cleanup;
		}
		int wr = write_line(pipe_to_child[1], pw);
		secure_clear(pw, strlen(pw));
		free(pw);
		if (wr != 0) {
			goto cleanup;
		}
	}

	/* Protocol loop: read commands from the Go binary until SUCCESS/FAILURE or
	 * the deadline fires. On Linux we additionally watch sshd's client socket
	 * with POLLRDHUP so a mid-auth disconnect tears down the Go child near
	 * instantly instead of letting it keep polling Authelia. */
	time_t deadline = monotonic_seconds() + cfg.timeout;

#ifdef __linux__
	int client_fd = find_client_socket(pamh);
#endif

	while (1) {
#ifdef __linux__
		int evt = wait_for_event(pipe_from_child[0], client_fd, deadline);
		if (evt == WAIT_CLIENT_GONE || evt == WAIT_DEADLINE || evt == WAIT_ERROR) {
			break;
		}
#endif

		int rc = read_line(pipe_from_child[0], line, sizeof(line), deadline);
		if (rc != 0) {
			break;
		}

		if (strncmp(line, CMD_PROMPT_HIDDEN, strlen(CMD_PROMPT_HIDDEN)) == 0) {
			char *response = NULL;
			const char *pt = line + strlen(CMD_PROMPT_HIDDEN);

			if (authelia_pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, pt, &response) != PAM_SUCCESS) {
				goto cleanup;
			}
			int wr;
			if (response != NULL) {
				wr = write_line(pipe_to_child[1], response);
				secure_clear(response, strlen(response));
				free(response);
			} else {
				wr = write_line(pipe_to_child[1], "");
			}
			if (wr != 0) {
				goto cleanup;
			}
		} else if (strncmp(line, CMD_PROMPT_MULTI_VISIBLE, strlen(CMD_PROMPT_MULTI_VISIBLE)) == 0) {
			const char *length_str = line + strlen(CMD_PROMPT_MULTI_VISIBLE);
			char *end = NULL;

			errno = 0;
			long length = strtol(length_str, &end, 10);

			if (errno != 0 || end == length_str || *end != '\0' ||
			    length <= 0 || length > MAX_PROMPT_PAYLOAD) {
				break;
			}

			char *payload = malloc((size_t)length + 1);
			if (payload == NULL) {
				goto cleanup;
			}

			if (read_bytes(pipe_from_child[0], payload, (size_t)length, deadline) != 0) {
				free(payload);
				goto cleanup;
			}

			payload[length] = '\0';

			char *response = NULL;
			int pr = authelia_pam_prompt(pamh, PAM_PROMPT_ECHO_ON, payload, &response);

			free(payload);

			if (pr != PAM_SUCCESS) {
				goto cleanup;
			}

			int wr;
			if (response != NULL) {
				wr = write_line(pipe_to_child[1], response);
				secure_clear(response, strlen(response));
				free(response);
			} else {
				wr = write_line(pipe_to_child[1], "");
			}
			if (wr != 0) {
				goto cleanup;
			}
		} else if (strncmp(line, CMD_PROMPT_VISIBLE, strlen(CMD_PROMPT_VISIBLE)) == 0) {
			char *response = NULL;
			const char *pt = line + strlen(CMD_PROMPT_VISIBLE);

			if (authelia_pam_prompt(pamh, PAM_PROMPT_ECHO_ON, pt, &response) != PAM_SUCCESS) {
				goto cleanup;
			}
			int wr;
			if (response != NULL) {
				wr = write_line(pipe_to_child[1], response);
				secure_clear(response, strlen(response));
				free(response);
			} else {
				wr = write_line(pipe_to_child[1], "");
			}
			if (wr != 0) {
				goto cleanup;
			}
		} else if (strncmp(line, CMD_INFO, strlen(CMD_INFO)) == 0) {
			const char *info_text = line + strlen(CMD_INFO);

			authelia_pam_prompt(pamh, PAM_TEXT_INFO, info_text, NULL);
		} else if (strcmp(line, CMD_SUCCESS) == 0) {
			ret = PAM_SUCCESS;
			break;
		} else if (strncmp(line, CMD_FAILURE, strlen(CMD_FAILURE)) == 0) {
			ret = PAM_AUTH_ERR;
			break;
		} else {
			/* Unknown command; treat as failure. */
			break;
		}
	}

cleanup:
	close(pipe_to_child[1]);
	close(pipe_from_child[0]);

	/* Wait for child or kill it on timeout. */
	if (waitpid(child, &status, WNOHANG) == 0) {
		kill(child, SIGTERM);
		waitpid(child, &status, 0);
	}

	secure_clear(line, sizeof(line));

	return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}
