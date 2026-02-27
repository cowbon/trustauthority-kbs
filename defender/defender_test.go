/*
 * Copyright (C) 2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package defender

import (
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	d := New(5, time.Second, time.Minute)

	if d == nil || d.Max != 5 || d.Duration != time.Second || d.BanDuration != time.Minute || d.clients == nil {
		t.Error("Defender not initialized correctly")
	}
}

func TestClientMethods(t *testing.T) {
	now := time.Now()
	client := &Client{
		key:    "test-key",
		banned: true,
		expire: now.Add(time.Hour),
	}

	if client.Key() != "test-key" || !client.Banned() || client.BanExpired() {
		t.Error("Client methods failed")
	}

	client.expire = now.Add(-time.Hour)
	if !client.BanExpired() {
		t.Error("Ban should be expired")
	}
}

func TestInc(t *testing.T) {
	d := New(3, time.Millisecond*100, time.Second)

	// Within limit
	for i := 0; i < 3; i++ {
		if d.Inc("client-1") {
			t.Errorf("Request %d should not be banned (limit is 3)", i+1)
		}
	}

	// Exceeds limit
	if !d.Inc("client-1") {
		t.Error("4th request should be banned")
	}

	client, _ := d.Client("client-1")
	if !client.banned {
		t.Error("Client should be banned")
	}

	// Test ban expiration
	time.Sleep(time.Second + time.Millisecond*50)
	if d.Inc("client-1") {
		t.Error("Should not be banned after ban expires")
	}
}

func TestBanList(t *testing.T) {
	d := New(2, time.Second, time.Minute)

	// Empty list
	if len(d.BanList()) != 0 {
		t.Error("Expected empty ban list")
	}

	// Ban some clients
	d.Inc("client-1")
	d.Inc("client-1")
	d.Inc("client-1")

	d.Inc("client-2")
	d.Inc("client-2")
	d.Inc("client-2")

	banList := d.BanList()
	if len(banList) != 2 {
		t.Errorf("Expected 2 banned clients, got %d", len(banList))
	}
}

func TestRemoveClient(t *testing.T) {
	d := New(5, time.Second, time.Minute)

	d.Inc("client-1")
	d.RemoveClient("client-1")

	if _, found := d.Client("client-1"); found {
		t.Error("Client should be removed")
	}

	// Remove non-existent
	d.RemoveClient("non-existent")
}

func TestCleanup(t *testing.T) {
	d := New(1, time.Millisecond*50, time.Millisecond*100)

	// Ban two clients
	d.Inc("client-1")
	d.Inc("client-1")

	d.Inc("client-2")
	d.Inc("client-2")

	time.Sleep(time.Millisecond * 150)

	d.Cleanup()

	if len(d.clients) != 0 {
		t.Errorf("Expected all clients cleaned up, got %d", len(d.clients))
	}
}

func TestCleanupTask(t *testing.T) {
	d := New(1, time.Millisecond*10, time.Millisecond*50)

	quit := make(chan struct{})
	go d.CleanupTask(quit)

	d.Inc("client-1")
	d.Inc("client-1")

	time.Sleep(time.Millisecond * 100)

	close(quit)
	time.Sleep(time.Millisecond * 50)
}

func TestConcurrentInc(t *testing.T) {
	d := New(100, time.Second, time.Minute)
	key := "concurrent-client"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Inc(key)
		}()
	}

	wg.Wait()

	client, found := d.Client(key)
	if !found || client.Banned() {
		t.Error("Expected client to exist and not be banned yet")
	}
}
