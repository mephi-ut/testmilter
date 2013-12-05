
// === Includes ===

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
#include <syslog.h>

// === Code ===

// See: http://www.postfix.org/MILTER_README.html
static const char *macros[] = {
	"i",
	"j",
	"_",
	"{auth_authen}",
	"{auth_author}",
	"{auth_type}",
	"{client_addr}",
	"{client_connections}",
	"{client_name}",
	"{client_port}",
	"{client_ptr}",
	"{cert_issuer}",
	"{cert_subject}",
	"{cipher_bits}",
	"{cipher}",
	"{daemon_name}",
	"{mail_addr}",
	"{mail_host}",
	"{mail_mailer}",
	"{rcpt_addr}",
	"{rcpt_host}",
	"{rcpt_mailer}",
	"{tls_version}",
	"v",
	NULL
};

void check_macros(SMFICTX *ctx) {
	int i;
	char *symval;

	i=0;
	while(macros[i]) {
		if((symval = smfi_getsymval(ctx, (char *)macros[i])) != 0)
			syslog(LOG_NOTICE, "check_macros: \"%s\" == \"%s\".\n", macros[i], symval);
		i++;
	}

	return;
}

extern sfsistat testmilter_cleanup(SMFICTX *, bool);

sfsistat testmilter_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	syslog(LOG_NOTICE, "testmilter_connect(ctx, \"%s\", hostaddr)\n", hostname);
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_helo(SMFICTX *ctx, char *helohost) {
	syslog(LOG_NOTICE, "testmilter_helo(ctx, \"%s\", helo)\n", helohost);
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_envfrom(SMFICTX *ctx, char **argv) {
	syslog(LOG_NOTICE, "testmilter_envfrom(ctx, argv):\n");
	if(argv == NULL) {
		check_macros(ctx);
		return SMFIS_CONTINUE;
	}
	int i=0;

	while(argv[i]) {
		syslog(LOG_NOTICE, "testmilter_envfrom(ctx, argv): from: \"%s\"\n", argv[i]);
		i++;
	}
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_envrcpt(SMFICTX *ctx, char **argv) {
	syslog(LOG_NOTICE, "testmilter_envrcpt(ctx, argv):\n");
	if(argv == NULL) {
		check_macros(ctx);
		return SMFIS_CONTINUE;
	}

	int i=0;

	while(argv[i]) {
		syslog(LOG_NOTICE, "testmilter_envrcpt(ctx, argv): rcpt: \"%s\"\n", argv[i]);
		i++;
	}
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_header(SMFICTX *ctx, char *headerf, char *headerv) {
	syslog(LOG_NOTICE, "testmilter_header(ctx, \"%s\", \"%s\")\n", headerf, headerv);
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_eoh(SMFICTX *ctx) {
	syslog(LOG_NOTICE, "testmilter_eoh(ctx)\n");
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) {
	syslog(LOG_NOTICE, "testmilter_body(ctx, bodyp, %lu)\n", bodylen);
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_eom(SMFICTX *ctx) {
	syslog(LOG_NOTICE, "testmilter_eom(ctx)\n");
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_abort(SMFICTX *ctx) {
	syslog(LOG_NOTICE, "testmilter_abort(ctx)\n");
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_close(SMFICTX *ctx) {
	syslog(LOG_NOTICE, "testmilter_close(ctx)\n");
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_unknown(SMFICTX *ctx, const char *cmd) {
	syslog(LOG_NOTICE, "testmilter_unknown(ctx, \"%s\")\n", cmd);
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_data(SMFICTX *ctx) {
	syslog(LOG_NOTICE, "testmilter_data(ctx)\n");
	check_macros(ctx);
	return SMFIS_CONTINUE;
}

sfsistat testmilter_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
	SMFICTX *ctx;
	unsigned long f0;
	unsigned long f1;
	unsigned long f2;
	unsigned long f3;
	unsigned long *pf0;
	unsigned long *pf1;
	unsigned long *pf2;
	unsigned long *pf3;
{
#if 0
	*pf0 |=  SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_CHGBODY | SMFIF_ADDRCPT |
		SMFIF_ADDRCPT_PAR | SMFIF_DELRCPT | SMFIF_QUARANTINE | 
		SMFIF_CHGFROM | SMFIF_SETSYMLIST;

	*pf1 |= 	SMFIP_RCPT_REJ | SMFIP_SKIP | SMFIP_NR_CONN | SMFIP_NR_HELO | 
		SMFIP_NR_MAIL | SMFIP_NR_RCPT | SMFIP_NR_DATA | SMFIP_NR_UNKN | 
		SMFIP_NR_EOH | SMFIP_NR_BODY | SMFIP_NR_HDR;

//	*pf0 = f0;
//	*pf1 = f1;

	*pf2 = 0;
	*pf3 = 0;

	check_macros(ctx);
	return SMFIS_CONTINUE;
#else
	*pf0 = f0;
	*pf1 = SMFIP_RCPT_REJ;
	syslog(LOG_NOTICE, "testmilter_negotiate(ctx, %lu, %lu, %lu, %lu,"
		" %lu, %lu, %lu, %lu)\n",
		f0, f1, f2, f3, *pf0, *pf1, *pf2, *pf3);
	return SMFIS_CONTINUE;
	//return SMFIS_ALL_OPTS;
#endif
}

static void usage(const char *path) {
	fprintf(stderr, "Usage: %s -p socket-addr [-t timeout]\n",
		path);
}

int main(int argc, char *argv[]) {
	struct smfiDesc mailfilterdesc = {
		"testmilter",			// filter name
		SMFI_VERSION,			// version code -- do not change
		SMFIF_ADDHDRS|SMFIF_ADDRCPT,	// flags
		testmilter_connect,		// connection info filter
		testmilter_helo,		// SMTP HELO command filter
		testmilter_envfrom,		// envelope sender filter
		testmilter_envrcpt,		// envelope recipient filter
		testmilter_header,		// header filter
		testmilter_eoh,			// end of header
		testmilter_body,		// body block filter
		testmilter_eom,			// end of message
		testmilter_abort,		// message aborted
		testmilter_close,		// connection cleanup
		testmilter_unknown,		// unknown SMTP commands
		testmilter_data,		// DATA command
		testmilter_negotiate		// Once, at the start of each SMTP connection
	};

	char setconn = 0;
	int c;
	const char *args = "p:t:h";
	extern char *optarg;
	// Process command line options
	while ((c = getopt(argc, argv, args)) != -1) {
		switch (c) {
			case 'p':
				if (optarg == NULL || *optarg == '\0')
				{
					(void)fprintf(stderr, "Illegal conn: %s\n",
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_setconn(optarg) == MI_FAILURE)
				{
					(void)fprintf(stderr,
						"smfi_setconn failed\n");
					exit(EX_SOFTWARE);
				}

				if (strncasecmp(optarg, "unix:", 5) == 0)
					unlink(optarg + 5);
				else if (strncasecmp(optarg, "local:", 6) == 0)
					unlink(optarg + 6);
				setconn = 1;
				break;
			case 't':
				if (optarg == NULL || *optarg == '\0') {
					(void)fprintf(stderr, "Illegal timeout: %s\n", 
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_settimeout(atoi(optarg)) == MI_FAILURE) {
					(void)fprintf(stderr,
						"smfi_settimeout failed\n");
					exit(EX_SOFTWARE);
				}
				break;
			case 'h':
			default:
				usage(argv[0]);
				exit(EX_USAGE);
		}
	}
	if (!setconn) {
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}
	if (smfi_register(mailfilterdesc) == MI_FAILURE) {
		fprintf(stderr, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	}
	openlog(NULL, LOG_PID, LOG_MAIL);
	int ret = smfi_main();
	closelog();
	return ret;
}

