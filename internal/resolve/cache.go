package resolve

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	msg     *dns.Msg
	expires time.Time
}

// Cache is a simple positive/negative response cache.
type Cache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	max   int
}

// NewCache creates a cache with max entries.
func NewCache(max int) *Cache {
	if max <= 0 {
		max = 4096
	}
	return &Cache{items: make(map[string]cacheEntry), max: max}
}

func cacheKey(name string, qtype uint16) string {
	return name + "|" + dns.TypeToString[qtype]
}

// Get returns a cached message if still valid.
func (c *Cache) Get(name string, qtype uint16) (*dns.Msg, bool) {
	c.mu.RLock()
	e, ok := c.items[cacheKey(name, qtype)]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		if ok {
			c.mu.Lock()
			delete(c.items, cacheKey(name, qtype))
			c.mu.Unlock()
		}
		return nil, false
	}
	return e.msg.Copy(), true
}

// Put stores a response.
func (c *Cache) Put(name string, qtype uint16, msg *dns.Msg, ttl time.Duration) {
	if msg == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.max {
		// drop arbitrary ~25%
		n := 0
		for k := range c.items {
			delete(c.items, k)
			n++
			if n > c.max/4 {
				break
			}
		}
	}
	c.items[cacheKey(name, qtype)] = cacheEntry{msg: msg.Copy(), expires: time.Now().Add(ttl)}
}
