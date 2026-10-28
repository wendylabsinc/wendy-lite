# Serialized crypto and retained context admission

This layer replaces the synchronous baseline facade with one optional
preemptible crypto worker and a one-item handoff. Baseline calls stay inline
until the mesh starts the worker. One callback owns a lent context at a time;
established I/O on unrelated contexts is not locked behind a handshake.
Retained handshake admission is separate from the CPU queue.

The later actor starts/stops this worker and binds itself as nonblocking; the
existing outer server adapter supplies I/O-worker polling when native consumers
are installed. This layer adds no active task while the native runtime is OFF.
Task reservations use the reviewed common task lifecycle helper.
