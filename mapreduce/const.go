package mapreduce

import (
	"time"
)

const (
	QUEUE_BATCH_SIZE  = 1024
	FLUSH_INTERVAL    = time.Minute
	MINUTE            = 60
	MAX_HASHMAP_WIDTH = 32
)
