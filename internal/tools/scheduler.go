// cron.go
package tools

import (
	"sync"

	"github.com/labstack/gommon/log"
	"github.com/robfig/cron/v3"
)

type Job struct {
	ID      string
	EntryID cron.EntryID
}

var (
	cronScheduler *cron.Cron
	jobs          = make(map[string]Job)
	jobMutex      sync.Mutex
	once          sync.Once
)

// init
func init() {
	once.Do(func() {
		log.Info("Initializing cron scheduler...")
		cronScheduler = cron.New(cron.WithSeconds()) // ← seconds enabled!
		cronScheduler.Start()
	})
}

// AddJob
func AddJob(id string, schedule string, task func()) error {
	jobMutex.Lock()
	defer jobMutex.Unlock()

	if _, exists := jobs[id]; exists {
		log.Warnf("Job with ID %s already exists, skipping", id)
		return nil
	}

	entryID, err := cronScheduler.AddFunc(schedule, task)
	if err != nil {
		return err
	}

	jobs[id] = Job{
		ID:      id,
		EntryID: entryID,
	}
	log.Infof("Scheduled job ID: %s", id)
	return nil
}

func UpdateJob(id string, schedule string, task func()) error {
	jobMutex.Lock()
	defer jobMutex.Unlock()

	job, exists := jobs[id]
	if !exists {
		log.Errorf("Job with ID %s not found", id)
		return nil
	}

	cronScheduler.Remove(job.EntryID)

	entryID, err := cronScheduler.AddFunc(schedule, task)
	if err != nil {
		return err
	}

	jobs[id] = Job{
		ID:      id,
		EntryID: entryID,
	}
	log.Infof("Updated job ID: %s", id)
	return nil
}

func RemoveJob(id string) {
	jobMutex.Lock()
	defer jobMutex.Unlock()

	job, ok := jobs[id]
	if !ok {
		log.Errorf("Job with ID %s not found", id)
		return
	}

	cronScheduler.Remove(job.EntryID)
	delete(jobs, id)
	log.Infof("Removed job ID: %s", id)
}

// Graceful shutdown — call this in main() or tests
func ShutdownCron() {
	if cronScheduler != nil {
		log.Info("Shutting down cron scheduler...")
		cronScheduler.Stop()
	}
}
