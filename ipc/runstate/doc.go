// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package runstate folds a scan's progress events into the current run state
// and serves that state to observers as a snapshot followed by a live feed.
//
// RunState is a pure reducer over progress.Event: the latest scan_start, the
// latest counts per stage, one host per IP (capped, with a truncated flag) and
// running error and warning counts. Replay turns that state back into a short
// sequence of ordinary progress events, so an observer that joins mid-run
// processes the snapshot through the same code path as the live stream.
//
// Hub owns one RunState per run and fans every published event out to its
// subscribers. Three properties hold:
//
//   - Publishing never blocks. Each subscriber has a bounded queue; a
//     subscriber whose queue is full is dropped and told so through Lagged.
//     A frozen observer therefore cannot stall a running scan.
//   - Subscribing is atomic with respect to publishing. The snapshot is taken
//     and the queue is registered under the same lock that Publish holds, so
//     the first live event a subscriber sees is exactly the one after the
//     snapshot's LastSeq: nothing is lost and nothing is duplicated.
//   - Observers in the same process use the same feed (SubscribeFunc), so an
//     in-process forwarder needs no protocol of its own.
//
// The package depends only on the standard library and the progress package,
// so it can be used without the ipc server.
package runstate
