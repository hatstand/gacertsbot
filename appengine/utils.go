package appengine

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/taskqueue"
)

// delayFunc creates and schedules a taskqueue task to run the given function
// in a few seconds.  It schedules it on the appengine module and instance that
// is serving the current request.  It configures some sensible retry options.
func delayFunc(c context.Context, fn *delay.Function, args ...interface{}) error {
	task, err := fn.Task(args...)
	if err != nil {
		return fmt.Errorf("Failed to create task: %v", err)
	}

	// Ensure we run on the same module and version.
	hostname, err := appengine.ModuleHostname(c, "", "", "")
	if err != nil {
		return err
	}
	task.Header = http.Header{"Host": []string{hostname}}

	// Set some sensible retry options.
	task.RetryOptions = &taskqueue.RetryOptions{
		RetryLimit: 10,
		MinBackoff: 5 * time.Second,
		MaxBackoff: 30 * time.Second,
	}

	// Schedule the task.
	task, err = taskqueue.Add(c, task, "")
	if err != nil {
		return err
	}
	log.Infof(c, "Scheduled task %s", task.Name)
	return nil
}

// HandlerFunc is an HTTP handler that takes a context and returns an error.
type HandlerFunc func(context.Context, http.ResponseWriter, *http.Request) error

// wrapHTTPHandler turns a HandlerFunc into an http.HandlerFunc for passing to
// HTTP libraries.
func wrapHTTPHandler(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := h(c, w, r); err != nil {
			log.Errorf(c, "%v", err)
			http.Error(w, err.Error(), 500)
		}
	}
}
