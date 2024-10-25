package pino

import "sync"

type Workers struct {
	tasks     chan func()
	waitGroup sync.WaitGroup
	poolCount int
}

func (workers *Workers) Start() {
	for i := 0; i < workers.poolCount; i++ {
		workers.waitGroup.Add(1)

		go func() {
			defer workers.waitGroup.Done()
			for task := range workers.tasks {
				task()
			}
		}()
	}
}

func (workers *Workers) Do(work func()) {
	workers.tasks <- work
}

func (workers *Workers) ShutDown() {
	close(workers.tasks)
	workers.waitGroup.Wait()
}

func NewWorkers(poolCount int) *Workers {
	return &Workers{
		tasks:     make(chan func(), poolCount),
		poolCount: poolCount,
	}
}
