#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <X11/SM/SMlib.h>
#include <X11/ICE/ICElib.h>

#include "gtkui.h"

#define trace(...) { fprintf(stderr, __VA_ARGS__); }

static char path[PATH_MAX];

static void
save_yourself_cb (SmcConn conn, SmPointer client_data, int save_type, Bool shutdown, int interact_style, Bool fast)
{
    trace ("xsession: save yourself\n");
    SmcSaveYourselfDone (conn, True);
}

static void
save_complete_cb (SmcConn conn, SmPointer client_data)
{
    trace ("xsession: save complete\n");
}

static void
die_cb (SmcConn conn, SmPointer client_data)
{
    trace ("xsession: die\n");
    gtkui_quit();
}

static void
shutdown_cancelled_cb (SmcConn conn, SmPointer client_data)
{
    trace ("xsession: shutdown cancelled\n");
}

static void
ice_watch (IceConn ice_conn, IcePointer client_data, Bool opening, IcePointer *watch_data)
{
    xsess_conn_t *xsess_conn = client_data;
    xsess_conn->fd = IceConnectionNumber (ice_conn);
    xsess_conn->ice_conn = ice_conn;
    gtkui_xsess_watch_fd (xsess_conn, opening == True);
}

void
xsession_process_messages (xsess_conn_t *xsess_conn)
{
    trace ("xsession: IceProcessMessages\n");
    IceProcessMessages (xsess_conn->ice_conn, NULL, NULL);
}

void
xsession_connection_died (xsess_conn_t *xsess_conn)
{
    trace ("xsession: ICE connection died\n");
}

static char *
load_current_sess()
{
    char sessid[128];
    FILE *f;
    size_t len;

    f = fopen (path, "rt");
    if (!f)
        return NULL;

    if (!fgets (sessid, sizeof (sessid), f))
        return NULL;

    len = strlen (sessid);
    if (sessid[len-1] != '\n') //line truncated
        return NULL;
    sessid[len-1] = '\0';
    return strdup (sessid);
}

int
xsession_start (xsess_conn_t *xsess_conn)
{
    IceAddConnectionWatch (&ice_watch, xsess_conn);

    SmcCallbacks callbacks = {
        .save_yourself = {.callback = &save_yourself_cb},
        .save_complete = {.callback = &save_complete_cb},
        .die = {.callback = &die_cb},
        .shutdown_cancelled = {.callback = &shutdown_cancelled_cb}
    };

    char errmsg[1024];
    char *newsessid;

    SmcConn conn = SmcOpenConnection (
        NULL,
        NULL,
        SmProtoMajor, SmProtoMinor,
        SmcSaveYourselfProcMask | SmcSaveCompleteProcMask | SmcDieProcMask | SmcShutdownCancelledProcMask,
        &callbacks,
        NULL,
        &newsessid,
        sizeof (errmsg), errmsg
    );

    if (!conn)
    {
        trace ("xsession: SmcOpenConnection error: %s\n", errmsg);
        return 0;
    }

    trace ("xsession: sessid: %s\n", newsessid);

    xsess_conn->sessid = strdup (newsessid);

    struct passwd *pw = getpwuid (geteuid());
    char *user = pw ? pw->pw_name : "<unknown>";

    char spid[24];
    snprintf (spid, sizeof(spid), "%llu", (unsigned long long)getpid());

    char self[PATH_MAX];
    if (readlink ("/proc/self/exe", self, sizeof (self)) == -1)
        strncpy (self, "deadbeef", sizeof (self));

    SmPropValue deadbeef_val = {.value = "deadbeef", .length = 8};
    SmPropValue user_id_val = {.value = user, .length = strlen (user)};
    SmPropValue pid_val = {.value = spid, .length = strlen (spid)};
    SmPropValue self_val = {.value = self, .length = strlen (self)};

    SmProp props[] = {
        {.name = SmProgram, .type = SmARRAY8, .num_vals = 1, .vals = &deadbeef_val},
        {.name = SmUserID, .type = SmARRAY8, .num_vals = 1, .vals = &user_id_val},
        {.name = SmProcessID, .type = SmARRAY8, .num_vals = 1, .vals = &pid_val},
        {.name = SmCloneCommand, .type = SmLISTofARRAY8, .num_vals = 1, .vals = &self_val},
        {.name = SmRestartCommand, .type = SmLISTofARRAY8, .num_vals = 1, .vals = &self_val},
    };

    SmProp *pprops[] = {&props[0], &props[1], &props[2], &props[3], &props[4]};

    int num_props = 5;
    SmcSetProperties (conn, num_props, &pprops[0]);
    return 1;
}
