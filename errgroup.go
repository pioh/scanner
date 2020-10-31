package main

import (
	"fmt"
	"sync"
)

type ErrGroup struct {
	sync.Mutex
	sync.WaitGroup

	err error
}

func (e *ErrGroup) Go(foo func() error) {
	e.Add(1)
	go func() {
		defer e.Done()

		err := foo()
		if err == nil {
			return
		}

		e.Lock()
		defer e.Unlock()

		if e.err != nil {
			e.err = fmt.Errorf("%v\n%w", e.err, err)
		} else {
			e.err = fmt.Errorf("%w", err)
		}
	}()
}

func (e *ErrGroup) Wait() error {
	e.WaitGroup.Wait()
	return e.err
}
