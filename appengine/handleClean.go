package appengine

import (
	"math/rand"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/delay"
	"google.golang.org/appengine/log"
)

const (
	asyncCleanupProbability = 0.2
)

func maybeTriggerAsyncCleanup(c context.Context) {
	if rand.Float64() < asyncCleanupProbability {
		delayFunc(c, cleanFunc)
	}
}

var cleanFunc = delay.Func("clean",
	func(c context.Context) error {
		ops, err := GetAllCreateOperations(c)
		if err != nil {
			return err
		}

		var expiredKeys []*datastore.Key

		now := time.Now()
		for _, op := range ops {
			if now.After(op.Accepted.Add(createOperationHardExpiry)) {
				expiredKeys = append(expiredKeys, op.Key)
			}
		}

		if len(expiredKeys) == 0 {
			log.Infof(c, "Nothing to clean up")
			return nil
		}

		log.Infof(c, "Deleting %d expired create operations...", len(expiredKeys))
		return datastore.DeleteMulti(c, expiredKeys)
	})
