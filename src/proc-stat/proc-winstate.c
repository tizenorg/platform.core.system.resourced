#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <resourced.h>

#include "proc-winstate.h"
#include "proc-main.h"
#include "lowmem-process.h"
#include "trace.h"

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <Ecore.h>
#include <Ecore_X.h>
#include <Ecore_Evas.h>
#include <Ecore_Input_Evas.h>

static Atom a_pid;
static Ecore_Event_Handler *hvchange;

static pid_t __get_win_pid(Display *d, Window win)
{
	int r;
	pid_t pid;

	Atom a_type;
	int format;
	unsigned long nitems;
	unsigned long bytes_after;
	unsigned char *prop_ret;
	XWindowAttributes attr;

	//_retv_if(d == NULL || !a_pid, -1);

	if (!XGetWindowAttributes(d, win, &attr))
		return -1;

	if (attr.override_redirect || attr.class == InputOnly)
		return -1;

	prop_ret = NULL;
	r = XGetWindowProperty(d, win, a_pid, 0, 1, False, XA_CARDINAL,
			       &a_type, &format, &nitems, &bytes_after,
			       &prop_ret);
	if (r != Success || prop_ret == NULL)
		return -1;

	if (a_type == XA_CARDINAL && format == 32)
		pid = *(unsigned long *)prop_ret;
	else
		pid = -1;

	XFree(prop_ret);

	return pid;
}


static int __find_win(Display *d, Window *win, pid_t pid)
{
	int r;
	pid_t p;
	unsigned int n;
	Window root, parent, *child;

	p = __get_win_pid(d, *win);
	if (p == pid)
		return 1;

	r = XQueryTree(d, *win, &root, &parent, &child, &n);
	if (r) {
		int i;
		int found = 0;

		for (i = 0; i < n; i++) {
			found = __find_win(d, &child[i], pid);
			if (found) {
				*win = child[i];
				break;
			}
		}
		XFree(child);

		if (found)
			return 1;
	}

	return 0;
}

static inline int _get_pid(Ecore_X_Window win)
{
	int pid;
	Ecore_X_Atom atom;
	unsigned char *in_pid = NULL;
	int num;

	atom = ecore_x_atom_get("X_CLIENT_PID");
	if (ecore_x_window_prop_property_get(win, atom, ECORE_X_ATOM_CARDINAL,
				sizeof(int), &in_pid, &num) == EINA_FALSE) {
		if(in_pid != NULL) {
			free(in_pid);
			in_pid = NULL;
		}
		if (ecore_x_netwm_pid_get(win, &pid) == EINA_FALSE) {
			_E("Failed to get PID from a window 0x%X", win);
			return -EINVAL;
		}
	} else {
		pid = *(int *)in_pid;
		free(in_pid);
	}

	return pid;
}

static Eina_Bool __proc_visibility_cb(void *data, int type, void *event)
{
	Ecore_X_Event_Window_Visibility_Change *ev;
	int pid, oom_score_adj;

	ev = event;

	pid = _get_pid(ev->win);

	_D("pid : %d, bvisibility : %d", pid, ev->fully_obscured);

	if (get_proc_oom_score_adj(pid, &oom_score_adj) < 0) {
		_E("Failed to get oom_score_adj");
		return ECORE_CALLBACK_RENEW;
	}

	if (oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED) {
		/* init oom_score_value */
		set_proc_oom_score_adj(pid, OOMADJ_INIT);
	}

	return ECORE_CALLBACK_RENEW;

}

int proc_add_visibiliry(int pid)
{
	int found;
	Display *d;
	Window win;

	d = XOpenDisplay(NULL);

	if (d == NULL) {
		_E("XOpenDisplay return NULL, pid = %d", pid);
		return RESOURCED_ERROR_FAIL;
	}

	win = XDefaultRootWindow(d);

	if (!a_pid)
		a_pid = XInternAtom(d, "_NET_WM_PID", True);

	found = __find_win(d, &win, pid);

	_D("pid %d, win %x, display %x, found %d", pid, win, d, found);

	if (!found) {
		XCloseDisplay(d);
		errno = ENOENT;
		return RESOURCED_ERROR_FAIL;
	}

	ecore_x_window_client_sniff(win);
	return RESOURCED_ERROR_OK;
}


int proc_win_status_init(void)
{
	ecore_x_init(NULL);
	hvchange =
	    ecore_event_handler_add(ECORE_X_EVENT_WINDOW_VISIBILITY_CHANGE,
				    __proc_visibility_cb, NULL);

	return RESOURCED_ERROR_OK;
}

